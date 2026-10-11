// test/video_jump_stack_test.dart
// The limited video jump-history stack: push/trim/pop, the limit-1 case, what
// lowering the limit under the current size does, and the fact that only the
// limit is persisted.
//
// The stack is a provider (`providers/video_jump_stack.dart`) rather than a
// field of the player screen's State, which is what makes it drivable here: the
// player screen creates a real media_kit `Player` in its first frame, so it
// cannot be mounted in a widget test. Because it is a provider it also survives
// the `pushReplacement` a jump performs (a field would be born empty in the
// incoming screen) and is readable by the Related list's exclusion.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/providers/video_jump_stack.dart';
import 'package:rcrm_gui/services/settings_service.dart';

MediaItem _video(String name) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:18443/$name',
  type: MediaType.video,
  size: 1024,
  modified: DateTime(2024, 1, 1),
);

List<String> _names(List<MediaItem> items) => [for (final v in items) v.name];

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  ProviderContainer container() {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    return c;
  }

  test('a jump records the video it leaves, and back pops the newest first', () {
    final c = container();
    final stack = c.read(videoJumpStackProvider.notifier);

    // Nothing opened yet: back has nothing to return to.
    expect(c.read(videoJumpStackProvider), isEmpty);
    expect(stack.pop(), isNull);

    stack.push(_video('a.mp4'));
    stack.push(_video('b.mp4'));
    stack.push(_video('c.mp4'));

    // Newest last, so `top` is where back would go next.
    expect(_names(c.read(videoJumpStackProvider)), [
      'a.mp4',
      'b.mp4',
      'c.mp4',
    ]);
    expect(stack.top?.name, 'c.mp4');

    // Back pops the newest entry first (LIFO), then the one before it, then
    // there is nothing left and the player route pops as it always did.
    expect(stack.pop()?.name, 'c.mp4');
    expect(_names(c.read(videoJumpStackProvider)), ['a.mp4', 'b.mp4']);
    expect(stack.pop()?.name, 'b.mp4');
    expect(stack.pop()?.name, 'a.mp4');
    expect(stack.pop(), isNull);
    expect(c.read(videoJumpStackProvider), isEmpty);
  });

  test('the stack is capped at the limit, dropping the OLDEST entries', () async {
    final c = container();
    await c.read(uiSettingsProvider.notifier).setVideoJumpHistoryLimit(3);
    final stack = c.read(videoJumpStackProvider.notifier);

    for (final n in ['a', 'b', 'c', 'd', 'e']) {
      stack.push(_video('$n.mp4'));
    }

    expect(stack.limit, 3);
    expect(_names(c.read(videoJumpStackProvider)), [
      'c.mp4',
      'd.mp4',
      'e.mp4',
    ]);
  });

  test('a limit of 1 keeps exactly one back step', () async {
    final c = container();
    await c.read(uiSettingsProvider.notifier).setVideoJumpHistoryLimit(1);
    final stack = c.read(videoJumpStackProvider.notifier);

    stack.push(_video('a.mp4'));
    expect(_names(c.read(videoJumpStackProvider)), ['a.mp4']);

    // One more jump replaces it: the only step back is the video just left.
    stack.push(_video('b.mp4'));
    expect(_names(c.read(videoJumpStackProvider)), ['b.mp4']);
    expect(stack.pop()?.name, 'b.mp4');

    // And then back leaves the player, exactly as before the stack existed.
    expect(stack.pop(), isNull);
  });

  test('lowering the limit under the current size shrinks from the oldest end',
      () async {
    final c = container();
    final stack = c.read(videoJumpStackProvider.notifier);
    for (final n in ['a', 'b', 'c', 'd', 'e', 'f']) {
      stack.push(_video('$n.mp4'));
    }
    expect(_names(c.read(videoJumpStackProvider)), [
      'a.mp4',
      'b.mp4',
      'c.mp4',
      'd.mp4',
      'e.mp4',
      'f.mp4',
    ]);

    // The settings slider moved down: the entries furthest back go first, so
    // the immediate "back" step is the one thing that never changes.
    await c.read(uiSettingsProvider.notifier).setVideoJumpHistoryLimit(2);
    expect(_names(c.read(videoJumpStackProvider)), ['e.mp4', 'f.mp4']);
    expect(stack.pop()?.name, 'f.mp4');
    expect(stack.pop()?.name, 'e.mp4');
    expect(stack.pop(), isNull);
  });

  test('raising the limit again brings nothing back', () async {
    final c = container();
    await c.read(uiSettingsProvider.notifier).setVideoJumpHistoryLimit(2);
    final stack = c.read(videoJumpStackProvider.notifier);
    for (final n in ['a', 'b', 'c']) {
      stack.push(_video('$n.mp4'));
    }
    expect(_names(c.read(videoJumpStackProvider)), ['b.mp4', 'c.mp4']);

    await c.read(uiSettingsProvider.notifier).setVideoJumpHistoryLimit(5);
    expect(_names(c.read(videoJumpStackProvider)), ['b.mp4', 'c.mp4']);
  });

  test('the limit is clamped to the slider\'s range', () async {
    final c = container();
    final notifier = c.read(uiSettingsProvider.notifier);

    await notifier.setVideoJumpHistoryLimit(0);
    expect(c.read(uiSettingsProvider).videoJumpHistoryLimit, kVideoJumpHistoryMin);
    expect(await SettingsService().getVideoJumpHistoryLimit(), kVideoJumpHistoryMin);

    await notifier.setVideoJumpHistoryLimit(999);
    expect(
      c.read(uiSettingsProvider).videoJumpHistoryLimit,
      kVideoJumpHistoryMax,
    );
    expect(await SettingsService().getVideoJumpHistoryLimit(), kVideoJumpHistoryMax);
  });

  test('the limit is persisted and restored; the stack itself is not', () async {
    final c = container();
    await c.read(uiSettingsProvider.notifier).setVideoJumpHistoryLimit(4);
    c.read(videoJumpStackProvider.notifier).push(_video('a.mp4'));
    expect(await SettingsService().getVideoJumpHistoryLimit(), 4);

    // Relaunch: a fresh container plus the startup `load()` app.dart performs.
    // The setting comes back; the stack does not — it is session state and
    // nothing about it is written to disk.
    final relaunched = container();
    await relaunched.read(uiSettingsProvider.notifier).load();
    expect(relaunched.read(uiSettingsProvider).videoJumpHistoryLimit, 4);
    expect(relaunched.read(videoJumpStackProvider), isEmpty);
  });

  test('the exclusion set is exactly the stack\'s paths', () {
    final c = container();
    final stack = c.read(videoJumpStackProvider.notifier);
    expect(c.read(jumpExcludedPathsProvider), isEmpty);

    stack.push(_video('a.mp4'));
    stack.push(_video('b.mp4'));
    expect(c.read(jumpExcludedPathsProvider), {'/a.mp4', '/b.mp4'});

    stack.pop();
    expect(c.read(jumpExcludedPathsProvider), {'/a.mp4'});
  });

  test('jumping to a video already in the stack records a second entry', () {
    // Documented behaviour, not an accident: the stack is a history of the
    // route taken, not a set of videos, so back retraces A → B → A one step at
    // a time instead of forgetting the first A.
    final c = container();
    final stack = c.read(videoJumpStackProvider.notifier);
    final a = _video('a.mp4');

    stack.push(a);
    stack.push(_video('b.mp4'));
    stack.push(a);

    expect(_names(c.read(videoJumpStackProvider)), [
      'a.mp4',
      'b.mp4',
      'a.mp4',
    ]);
    expect(stack.pop()?.name, 'a.mp4');
    expect(stack.pop()?.name, 'b.mp4');
    expect(stack.pop()?.name, 'a.mp4');
  });
}
