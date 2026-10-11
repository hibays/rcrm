// test/thumb_cache_access_test.dart
// Reading the cache is an EVENT, and the grading has to see it — without the
// cache's own generation times being destroyed by the reading.
//
// Two claims, both against a real directory:
//
//  * a cache HIT is recorded, so the next grading knows the entry is hot. Before
//    the read the same entry has no access record at all, which is what makes
//    this a before/after proof rather than a restatement;
//  * the file's mtime is UNCHANGED by that read. mtime IS the generation time —
//    the axis the whole score is normalised against — so a read that refreshed it
//    would silently erase the difference between a cache that is being used and
//    one that was written once, and every old-and-hot entry would collapse into
//    "just generated". This is the assertion that keeps the two axes two.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/thumb_cache.dart';

void main() {
  late Directory temp;
  late Directory cacheDir;

  setUp(() async {
    ThumbCache.resetForTest();
    temp = await Directory.systemTemp.createTemp('rcrm_thumb_access_test');
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

  test('a read is recorded, and the generation time survives it', () async {
    const id = 'https://host/media/poster/one';
    const generationAge = Duration(days: 30);

    await ThumbCache.write(id, Uint8List.fromList([1, 2, 3, 4]));
    final entry = cacheDir.listSync().whereType<File>().single;
    // Make it look like a month-old entry: mtime is the generation time, and this
    // is the ONLY thing allowed to set it.
    await entry.setLastModified(DateTime.now().subtract(generationAge));
    final generatedAt = (await entry.stat()).modified;

    // Before the read: no access record, so the newest tier has no used time.
    final before = await ThumbCache.preview(maxBytes: 1);
    expect(before.graded, 1);
    expect(
      before.freshUsedAt,
      isNull,
      reason: 'nothing has read this entry yet, and we do not invent one',
    );

    final hit = await ThumbCache.read(id);
    expect(hit, isNotNull, reason: 'the write above is a cache hit by now');

    final after = await ThumbCache.preview(maxBytes: 1);
    expect(
      after.freshUsedAt,
      isNotNull,
      reason: 'the read recorded the access, so the grading can see it is hot',
    );
    expect(
      after.freshUsedAt!.isAfter(
        DateTime.now().subtract(const Duration(minutes: 5)),
      ),
      isTrue,
      reason: 'recorded as used just now, not as used when it was generated',
    );

    // The load-bearing one.
    expect(
      (await entry.stat()).modified,
      generatedAt,
      reason:
          'a read must NOT rewrite mtime: that field is the generation time, '
          'and the score is normalised against it',
    );
  });

  test('the file-based path records access too', () async {
    // `fileFor` is the mobile decode path (the caller opens the file itself), so
    // an access recorded only by `read` would leave every phone cache ungraded.
    const id = 'https://host/media/thumb/two';
    await ThumbCache.write(id, Uint8List.fromList([9]));
    expect((await ThumbCache.preview(maxBytes: 1)).freshUsedAt, isNull);

    final file = await ThumbCache.fileFor(id);
    expect(file, isNotNull);
    expect(
      (await file!.readAsBytes()).length,
      1,
      reason: 'the entry is really there, so this is a hit and not a phantom',
    );

    expect((await ThumbCache.preview(maxBytes: 1)).freshUsedAt, isNotNull);
  });
}
