// test/thumb_cache_access_log_test.dart
// The access log's own hygiene: it describes entries, so it must not outlive them.
//
// Deleting a cached thumbnail deletes its FILE, not its row — and the log is only
// ever written out IN FULL, so those rows would accumulate for the life of the
// install. The listing inside `preview` is the authority on what still exists, so
// that is where the in-memory map is pruned, and `manage` flushes the pruned
// truth out. This test is the difference between "we prune it" and "it is pruned".
//
// The log's rows are keyed by the ENTRY FILE NAME (the same FNV-1a hash as the
// cache file), not by the URL id the caller uses — so the assertions go through
// the directory listing, which is also what the code itself treats as truth.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/thumb_cache.dart';

void main() {
  late Directory temp;
  late Directory cacheDir;

  setUp(() async {
    ThumbCache.resetForTest();
    temp = await Directory.systemTemp.createTemp('rcrm_thumb_log_test');
    cacheDir = Directory('${temp.path}/._thumbs');
    await cacheDir.create(recursive: true);
    ThumbCache.overrideDir = temp;
    ThumbCache.enabled = true;
  });

  tearDown(() async {
    ThumbCache.enabled = false;
    ThumbCache.resetForTest();
    try {
      await temp.delete(recursive: true);
    } catch (_) {}
  });

  Set<String> entryNames() => {
    for (final f in cacheDir.listSync().whereType<File>())
      f.uri.pathSegments.last,
  };

  Future<List<String>> logRows() async {
    final log = File('${temp.path}/._thumbs_used'); // beside the entries
    if (!await log.exists()) return const [];
    return (await log.readAsString())
        .split('\n')
        .where((l) => l.trim().isNotEmpty)
        .toList();
  }

  test('a deleted entry\'s row does not survive the next flush', () async {
    await ThumbCache.write('gone', Uint8List.fromList([1]));
    await ThumbCache.write('stays', Uint8List.fromList([2]));
    await ThumbCache.read('gone');
    await ThumbCache.read('stays');

    final both = entryNames();
    expect(both, hasLength(2));

    // A budget nothing exceeds: this is the read of the cache and the flush, not
    // a clean-up.
    await ThumbCache.manage(maxBytes: 1024 * 1024);
    for (final name in both) {
      expect((await logRows()).join('\n'), contains(name));
    }
    expect(await logRows(), hasLength(2));

    // Now delete one entry and manage again: its row must go with it, and the
    // survivor's must stay.
    await ThumbCache.remove('gone');
    await ThumbCache.manage(maxBytes: 1024 * 1024);

    final survivor = entryNames().single;
    final rows = await logRows();
    expect(rows, hasLength(1), reason: 'one entry left, one row left');
    expect(rows.single, contains(survivor));
  });

  test('an entry that was never read has no row', () async {
    await ThumbCache.write('neverRead', Uint8List.fromList([1]));
    await ThumbCache.manage(maxBytes: 1024 * 1024);

    expect(await logRows(), isEmpty);
  });
}
