// test/thumb_cache_manage_test.dart
// The cache's MANAGEMENT, against a real directory.
//
// The rule is tested on its own in `thumb_cache_policy_test.dart`; what this file
// checks is the other half — that `ThumbCache.manage` reads the entries it needs
// (each file's own write time as the generation time, and its length as its
// size), hands them to that rule, and deletes exactly what came back. The
// directory is a temp one via the test seam, because the real cache location
// needs a platform plugin.
//
// The distinction the whole change is about: `clear()` deletes everything, and
// `manage()` must not — it spends the coldest entries and stops at the budget.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/thumb_cache.dart';
import 'package:rcrm_gui/utils/thumb_cache_policy.dart';

/// One entry per call, named so a failure says which tier it was meant to be in.
Future<File> _seed(
  Directory dir,
  String name, {
  required Duration age,
  int bytes = 100,
}) async {
  final f = File('${dir.path}/$name');
  await f.writeAsBytes(List<int>.filled(bytes, 7));
  await f.setLastModified(DateTime.now().subtract(age));
  return f;
}

void main() {
  late Directory temp;
  late Directory cacheDir;

  setUp(() async {
    ThumbCache.resetForTest();
    temp = await Directory.systemTemp.createTemp('rcrm_thumb_cache_test');
    cacheDir = Directory('${temp.path}/._thumbs');
    await cacheDir.create(recursive: true);
    ThumbCache.overrideDir = temp;
  });

  tearDown(() async {
    ThumbCache.resetForTest();
    try {
      await temp.delete(recursive: true);
    } catch (_) {}
  });

  test('manages instead of clearing: the coldest go, the newest stay', () async {
    // Three generations: an hour-old burst, yesterday's, and this minute's. One
    // entry per tier, 100 bytes each, and a budget that needs exactly one gone.
    await _seed(cacheDir, 'cold1', age: const Duration(days: 30));
    await _seed(cacheDir, 'warm1', age: const Duration(days: 1));
    await _seed(cacheDir, 'fresh1', age: const Duration(minutes: 1));

    final plan = await ThumbCache.manage(maxBytes: 250);

    expect(plan.cold, ['cold1']);
    expect(plan.warm, ['warm1']);
    expect(plan.fresh, ['fresh1']);
    expect(plan.drop, ['cold1']);
    expect(File('${cacheDir.path}/cold1').existsSync(), isFalse);
    expect(File('${cacheDir.path}/warm1').existsSync(), isTrue);
    expect(File('${cacheDir.path}/fresh1').existsSync(), isTrue);
  });

  test('a cache inside its budget is not touched at all', () async {
    await _seed(cacheDir, 'a', age: const Duration(days: 3));
    await _seed(cacheDir, 'b', age: const Duration(minutes: 2));

    final plan = await ThumbCache.manage(maxBytes: 10 * 1024 * 1024);

    expect(plan.drop, isEmpty);
    expect(plan.graded, 2);
    expect(cacheDir.listSync().whereType<File>(), hasLength(2));
  });

  test('the generation time it grades by is the file\'s own write time', () async {
    // Written in this order, ages the other way round: only the file's mtime can
    // tell them apart, so a policy fed the wrong field would pick the wrong one.
    await _seed(cacheDir, 'actuallyNew', age: const Duration(minutes: 1));
    await _seed(cacheDir, 'actuallyOld', age: const Duration(days: 10));
    await _seed(cacheDir, 'middle', age: const Duration(hours: 5));

    final plan = await ThumbCache.manage(maxBytes: 250);

    expect(plan.drop, ['actuallyOld']);
    expect(File('${cacheDir.path}/actuallyOld').existsSync(), isFalse);
    expect(File('${cacheDir.path}/actuallyNew').existsSync(), isTrue);
  });

  test('an empty or missing cache is not an error', () async {
    final plan = await ThumbCache.manage(maxBytes: 1000);
    expect(plan.graded, 0);
    expect(plan.drop, isEmpty);
    expect(
      describeThumbCachePlan(plan, formatBytes: ThumbCache.human),
      'cache is empty',
    );
  });

  test('the description counts the tiers it kept', () async {
    await _seed(cacheDir, 'a', age: const Duration(days: 9));
    await _seed(cacheDir, 'b', age: const Duration(days: 5));
    await _seed(cacheDir, 'c', age: const Duration(days: 1));

    final plan = await ThumbCache.manage(maxBytes: 150);
    final line = describeThumbCachePlan(plan, formatBytes: ThumbCache.human);

    expect(line, contains('cold'));
    expect(line, contains('warm'));
    expect(line, contains('fresh kept'));
  });
}
