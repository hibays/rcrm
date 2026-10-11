// services/thumb_cache_access_log.dart
// WHEN each cached thumbnail was last READ — the cache's second axis, kept apart
// from the entries themselves on purpose.
//
// It lives in its own file because it is a different kind of thing from the entry
// store: a text log with its own format, its own failure mode (a corrupt or missing
// log costs precision in the grading, never correctness), and its own reason to
// exist — the file's mtime IS the generation time, so a read must never rewrite it,
// and `stat().accessed` is unreliable on every platform we ship to. `ThumbCache`
// only calls into this; nothing here knows about budgets, scores or tiers.
//
// WHERE: `<app cache dir>/._thumbs_used`, i.e. BESIDE the entry directory
// (`._thumbs/`), never inside it. Inside, every caller that lists entries —
// `preview`, `sizeBytes`, `clear`, a test counting files — had to learn to skip it.
//
// FORMAT: one `<entry file name>\t<epoch millis>` per line, rewritten in full each
// flush. Orphan rows are pruned against the entries that still exist, or they would
// accumulate for the life of the install.

import 'dart:async';
import 'dart:io';

class ThumbCacheAccessLog {
  ThumbCacheAccessLog._();

  /// The log file for a cache whose ENTRIES live in [entriesDir].
  static File fileFor(Directory entriesDir) =>
      File('${entriesDir.parent.path}/._thumbs_used');

  /// How many reads may pass before the log is written out. The cache is read for
  /// every visible thumbnail, and this is bookkeeping for a background decision —
  /// it must not cost a write per image.
  static const int flushEvery = 64;

  static final Map<String, DateTime> _lastUsed = {};
  static int _sinceFlush = 0;
  static String? _loadedFrom;

  /// When [entryName] was last read, or null when nothing recorded a read — which
  /// is honest: we then know only when the entry was made.
  static DateTime? lastUsedAt(String entryName) => _lastUsed[entryName];

  /// Notes that [entryName] was just used, and flushes every [flushEvery] reads.
  ///
  /// In memory first, always: the in-flight decision must see it even if the write
  /// below never happens.
  static void note(String entryName, DateTime now) {
    _lastUsed[entryName] = now;
    if (++_sinceFlush >= flushEvery) {
      _sinceFlush = 0;
      unawaited(flush());
    }
  }

  /// Drops everything not in [alive] — the entries the store just listed, which is
  /// the only authority on what still exists. Deleting an entry does not delete its
  /// row, and the log is only ever written out in full, so without this the rows
  /// outlive their entries for the life of the install.
  static void pruneTo(Set<String> alive) =>
      _lastUsed.removeWhere((name, _) => !alive.contains(name));

  /// Reads the log for [entriesDir] once per process, keeping whichever time is
  /// NEWER: a read in this session is better information than the file's.
  static Future<void> load(Directory entriesDir) async {
    if (_loadedFrom == entriesDir.path) return;
    _loadedFrom = entriesDir.path;
    try {
      final f = fileFor(entriesDir);
      if (!await f.exists()) return;
      for (final line in await f.readAsLines()) {
        final tab = line.indexOf('\t');
        if (tab <= 0) continue;
        final ms = int.tryParse(line.substring(tab + 1));
        if (ms == null) continue;
        final name = line.substring(0, tab);
        final when = DateTime.fromMillisecondsSinceEpoch(ms);
        final known = _lastUsed[name];
        if (known == null || known.isBefore(when)) _lastUsed[name] = when;
      }
    } catch (_) {}
  }

  /// Writes the whole log out. Best-effort like everything here: losing it costs
  /// precision in the grading, never correctness.
  static Future<void> flush() async {
    try {
      final lines = [
        for (final e in _lastUsed.entries)
          '${e.key}\t${e.value.millisecondsSinceEpoch}',
      ];
      // The directory is created by the store; if it is not there yet there is
      // nothing cached, so there is nothing to record either.
      final dir = Directory(_loadedFrom ?? '');
      if (_loadedFrom == null || !await dir.exists()) return;
      await fileFor(dir).writeAsString('${lines.join('\n')}\n');
    } catch (_) {}
  }

  /// Puts this log's static state back the way a fresh process would find it.
  ///
  /// NOT `@visibleForTesting`: the entry store's own test hook (`ThumbCache.
  /// resetForTest`, which is) calls it, and the analyzer refuses a test-only member
  /// reached from another library. It is still only for tests in practice.
  static void reset() {
    _lastUsed.clear();
    _loadedFrom = null;
    _sinceFlush = 0;
  }
}
