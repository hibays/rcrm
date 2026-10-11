// services/thumb_cache.dart
// Optional on-disk thumbnail cache (video posters + small image thumbnails).
//
// Stored in the app's PRIVATE cache directory (getApplicationCacheDirectory) —
// not user-accessible. Gated by [enabled] (mirrored from settings; default ON
// for mobile, OFF for desktop). All ops are best-effort and never throw.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:path_provider/path_provider.dart';

import '../utils/thumb_cache_policy.dart';
import 'thumb_cache_access_log.dart';

class ThumbCache {
  ThumbCache._();

  /// Runtime gate, mirrored from the persisted setting. When false, all reads
  /// return null and writes are no-ops.
  static bool enabled = false;

  /// Stable cache id for a media URL: the file PATH only. The WebDAV
  /// host/port/user/password are randomly regenerated each session, so keying
  /// by the full URL would invalidate the cache on every launch.
  static String pathId(String url) {
    try {
      return Uri.parse(url).path;
    } catch (_) {
      return url;
    }
  }

  static Directory? _dir;

  /// Where the cache lives, for tests: `getApplicationCacheDirectory` needs a
  /// platform plugin, so a test that exercises [manage] points this at a temp
  /// directory instead.
  @visibleForTesting
  static Directory? overrideDir;

  /// Puts the static state back the way a fresh process would find it, for tests
  /// that point [overrideDir] somewhere else: the resolved directory, the access
  /// log's provenance and the limit are all memoized for the process's lifetime.
  @visibleForTesting
  static void resetForTest() {
    _dir = null;
    overrideDir = null;
    limitMb = 0;
    ThumbCacheAccessLog.reset();
  }

  /// How many entries are unlinked at once — see the loop in [manage].
  static const int _unlinkBatch = 16;

  /// How many entries are stat-ed at once — see the listing in [preview].
  static const int _statBatch = 32;

  static Future<Directory> _ensureDir() async {
    if (_dir != null) return _dir!;
    final base =
        overrideDir ?? await getApplicationCacheDirectory(); // app-private
    final d = Directory('${base.path}/._thumbs');
    if (!await d.exists()) await d.create(recursive: true);
    _dir = d;
    return d;
  }

  // FNV-1a 64-bit → hex filename (avoids a crypto dependency).
  static String _key(String s) {
    var h = 0xcbf29ce484222325;
    for (final c in s.codeUnits) {
      h ^= c;
      h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF;
    }
    return h.toRadixString(16);
  }

  static Future<Uint8List?> read(String id) async {
    if (!enabled) return null;
    try {
      final f = File('${(await _ensureDir()).path}/${_key(id)}');
      if (await f.exists()) {
        final bytes = await f.readAsBytes();
        // Deliberately NOT `setLastModified`: that field is the generation time.
        ThumbCacheAccessLog.note(_key(id), DateTime.now());
        return bytes;
      }
    } catch (_) {}
    return null;
  }

  /// The size the MANUAL clean-up trims the cache to, mirrored from settings:
  /// `0` (the default) is this platform's budget (96 MB mobile / 512 MB desktop),
  /// `>0` is that many MB.
  ///
  /// There is no automatic management: nothing prunes the cache on its own, and
  /// `write` only writes. A budget that only ever gets applied when the user asks
  /// for it is also the only kind that cannot surprise them about disk use.
  static int limitMb = 0;

  static Future<void> write(String id, Uint8List bytes) async {
    if (!enabled) return;
    try {
      final f = File('${(await _ensureDir()).path}/${_key(id)}');
      await f.writeAsBytes(bytes);
    } catch (_) {}
  }

  /// Mobile keeps a smaller cache; resolved once, like `ItemCacheLimit.isMobile`
  /// (this file deliberately has no Flutter dependency beyond the test seam).
  static final bool _isMobile = Platform.isAndroid || Platform.isIOS;

  /// The cached file for [id], or null when disabled. No existence check —
  /// callers that open the file must handle a missing entry (e.g. via
  /// `ImmutableBuffer.fromFilePath`, which throws). Saves one stat per cell.
  static Future<File?> fileFor(String id) async {
    if (!enabled) return null;
    try {
      // The decode path takes the FILE, not the bytes — and it is the main read
      // path on mobile, so the access has to be noted here too. A caller that
      // then fails to decode records a name for a file that is not there, which
      // the grading simply never sees (it grades what it lists).
      final key = _key(id);
      ThumbCacheAccessLog.note(key, DateTime.now());
      return File('${(await _ensureDir()).path}/$key');
    } catch (_) {
      return null;
    }
  }

  /// Delete the cache entry for [id] (best-effort). Used to heal corrupt
  /// cache files: a decode failure removes the bad entry so the next load
  /// regenerates instead of failing forever.
  static Future<void> remove(String id) async {
    if (!enabled) return;
    try {
      final f = File('${(await _ensureDir()).path}/${_key(id)}');
      if (await f.exists()) await f.delete();
    } catch (_) {}
  }

  /// Total size of all cached files, in bytes.
  static Future<int> sizeBytes() async {
    try {
      final d = await _ensureDir();
      var total = 0;
      await for (final e in d.list()) {
        if (e is File) total += await e.length();
      }
      return total;
    } catch (_) {
      return 0;
    }
  }

  /// Manage the cache instead of evicting it: grade every entry by when it was
  /// GENERATED (the file's own write time) and delete only the coldest, and only
  /// until the cache is back under budget.
  ///
  /// Returns what it decided, so a caller can report it (`describeThumbCachePlan`)
  /// rather than silently throwing bytes away. Best-effort, like everything else
  /// here: an entry that vanished between the listing and the delete is not an
  /// error. Runs whether or not the cache is [enabled] — switching it off leaves
  /// yesterday's files on disk, and those are exactly what wants managing.
  ///
  /// The rule itself is `planThumbCache` (`utils/thumb_cache_policy.dart`): pure,
  /// tested without a filesystem, and the reason this is management rather than
  /// the all-or-nothing [clear].
  static Future<ThumbCachePlan> manage({
    int? maxBytes,
    Set<ThumbCacheTier> spend = kAllThumbCacheTiers,
    bool dropWholeTiers = false,
  }) async {
    // [preview] does the reading and the grading; this only carries it out, so
    // what the dialog showed the user is exactly what runs — one listing, one
    // rule, no second copy to drift.
    final plan = await preview(
      maxBytes: maxBytes,
      spend: spend,
      dropWholeTiers: dropWholeTiers,
    );
    if (plan.drop.isEmpty) {
      // Still flush: managing is the one point where writing is expected, and
      // without this a session with fewer than `ThumbCacheAccessLog.flushEvery` reads would
      // record nothing at all — the accesses would exist only in memory and die
      // with the process.
      await ThumbCacheAccessLog.flush();
      return plan;
    }
    try {
      final d = await _ensureDir();
      // Unlinks run in bounded batches: `manage` may be asked to drop a third of a
      // large cache, and awaiting each delete in turn is the slowest honest way to
      // do it. Bounded, because handing a whole directory's worth of unlinks to the
      // filesystem at once is its own way to lose.
      for (var i = 0; i < plan.drop.length; i += _unlinkBatch) {
        final end = i + _unlinkBatch < plan.drop.length
            ? i + _unlinkBatch
            : plan.drop.length;
        await Future.wait([
          for (final name in plan.drop.sublist(i, end))
            File(
              '${d.path}/$name',
            ).delete().then<void>((_) {}, onError: (_) {}),
        ]);
      }
    } catch (_) {}
    return plan;
  }

  /// What [manage] WOULD do, without doing it — the grading made visible.
  ///
  /// The UI runs this before the user chooses, because a heuristic is only honest
  /// when it can be read: which tiers the cache falls into, what each one weighs,
  /// and where the boundaries land in TIME ([ThumbCachePlan.coldUpTo] and
  /// `.warmUpTo` are the two cut points, as dates).
  ///
  /// [spend] is the user's own choice of which tiers may go — passed straight to
  /// the rule, so the tiers they untick are the tiers that stay.
  static Future<ThumbCachePlan> preview({
    int? maxBytes,
    Set<ThumbCacheTier> spend = kAllThumbCacheTiers,
    bool dropWholeTiers = false,
  }) async {
    final budget =
        maxBytes ??
        thumbCacheBudgetBytes(isMobile: _isMobile, limitMb: limitMb);
    try {
      final d = await _ensureDir();
      // The access log is READ here (it is part of the grading's input) but not
      // WRITTEN: a preview must not touch the disk. It used to flush, which meant
      // opening the dialog wrote the log even with the cache switched off — and a
      // file the user never asked to create is exactly the kind of side effect a
      // preview should not have. Reads persist themselves (throttled, every
      // `ThumbCacheAccessLog.flushEvery` of them) and `manage` flushes what it applied.
      await ThumbCacheAccessLog.load(d);
      // Listing is one pass; the STATS go in bounded batches. A cache of 50k
      // thumbnails was 50k sequential filesystem round trips — the slowest part of
      // opening this dialog, and it is spent before the user sees a single row.
      // Bounded (not one `Future.wait` over the whole directory), because handing
      // a whole directory to the filesystem at once is its own way to lose.
      final files = <File>[];
      await for (final e in d.list()) {
        if (e is File) files.add(e);
      }
      final entries = <ThumbCacheEntry>[];
      for (var i = 0; i < files.length; i += _statBatch) {
        final end = i + _statBatch < files.length
            ? i + _statBatch
            : files.length;
        final batch = files.sublist(i, end);
        final stats = await Future.wait([
          for (final f in batch)
            f.stat().then<FileStat?>((s) => s, onError: (_) => null),
        ]);
        for (var j = 0; j < batch.length; j++) {
          final stat = stats[j];
          if (stat == null) continue;
          final name = batch[j].uri.pathSegments.last;
          entries.add(
            ThumbCacheEntry(
              name: name,
              generatedAt: stat.modified, // generation time
              lastUsedAt: ThumbCacheAccessLog.lastUsedAt(name),
              bytes: stat.size,
            ),
          );
        }
      }
      // The access log outlives the entries it describes: deleting an entry does
      // not delete its row, and the map is only ever written out IN FULL, so
      // those rows would accumulate for the life of the install. The listing
      // above is the authority on what still exists, so the map is pruned against
      // it here — and the next flush writes the pruned truth.
      final alive = {for (final e in entries) e.name};
      ThumbCacheAccessLog.pruneTo(alive);
      return planThumbCache(
        entries,
        maxBytes: budget,
        spend: spend,
        dropWholeTiers: dropWholeTiers,
      );
    } catch (_) {
      return const ThumbCachePlan(
        drop: [],
        fresh: [],
        warm: [],
        cold: [],
        keptBytes: 0,
        droppedBytes: 0,
      );
    }
  }

  /// Deletes EVERY cached entry — the blunt instrument this file used to be.
  ///
  /// Kept because "get rid of all of it" is a legitimate thing to ask for
  /// explicitly, but it is no longer how the cache is kept in bounds: that is
  /// [manage], which spares the newest tier and stops at the budget.
  static Future<void> clear() async {
    try {
      final d = await _ensureDir();
      await for (final e in d.list()) {
        if (e is File) {
          try {
            await e.delete();
          } catch (_) {}
        }
      }
    } catch (_) {}
  }

  static String human(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}
