// test/player_scrub_test.dart
// What the progress bar shows WHILE the user drags it.
//
// Regression: `_scrub` is already milliseconds (the slider reports a fraction and
// the write site scales it), but the label getter multiplied by the duration a
// second time, so half-way through a 42-minute video the bar printed ms × ms —
// the "random memory number" that appeared after the controls rewrite. These
// tests drive the slider exactly as the widget does and pin the label, the
// clamp, and the "duration not known yet" behaviour.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/player_controls.dart';

const _duration = Duration(minutes: 42, seconds: 5); // 2_525_000 ms
const _position = Duration(minutes: 1, seconds: 23);

Widget _host(Widget child) => MaterialApp(
  home: Scaffold(
    backgroundColor: Colors.black,
    body: Stack(
      children: [
        Positioned(left: 0, right: 0, bottom: 0, child: child),
      ],
    ),
  ),
);

Future<void> _pumpBar(
  WidgetTester tester, {
  required Duration duration,
  ValueChanged<Duration>? onSeek,
  ValueChanged<double>? onVolumeChanged,
  ValueChanged<bool>? onScrubActive,
}) async {
  await tester.binding.setSurfaceSize(const Size(900, 240));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    _host(
      PlayerControlBar(
        playing: true,
        position: _position,
        duration: duration,
        buffer: const Duration(minutes: 5),
        volume: 80,
        speed: 1.0,
        fullscreen: false,
        hasPrev: false,
        hasNext: false,
        hasEpisodes: false,
        onPlayPause: () {},
        onToggleMute: () {},
        onFullscreen: () {},
        onNext: () {},
        onPrev: () {},
        onEpisodes: () {},
        onSpeedChanged: (_) {},
        onSeek: onSeek,
        onVolumeChanged: onVolumeChanged,
        onScrubActive: onScrubActive,
      ),
    ),
  );
}

/// The bar carries TWO sliders (seek + volume), so pick by value rather than by
/// order: the seek slider's value is the played fraction (~0.033 here), the
/// volume slider's is 0.8.
Slider _sliderAt(WidgetTester tester, double value) => tester
    .widgetList<Slider>(find.byType(Slider))
    .firstWhere(
      (s) => (s.value - value).abs() < 0.05,
      orElse: () =>
          throw StateError('no slider near $value among '
              '${tester.widgetList<Slider>(find.byType(Slider)).length}'),
    );

/// The seek slider in its resting state: `position / duration`.
Slider _seekSlider(WidgetTester tester) =>
    _sliderAt(tester, _position.inMilliseconds / _duration.inMilliseconds);

/// The volume slider: `volume: 80` in the harness. Its scale is 0..100, unlike
/// the seek slider's 0..1 fraction.
Slider _volumeSlider(WidgetTester tester) => _sliderAt(tester, 80);

void main() {
  testWidgets('half-way through the drag shows half the duration', (
    tester,
  ) async {
    await _pumpBar(tester, duration: _duration, onSeek: (_) {});

    expect(find.text('01:23'), findsOneWidget, reason: 'position label');

    _seekSlider(tester).onChanged!(0.5);
    await tester.pump();

    // 2_525_000 / 2 = 1_262_500 ms = 21:02.5 → rounds to 21:03. The old code
    // printed this value MULTIPLIED by the duration again (7.9e12 ms).
    expect(find.text('21:03'), findsOneWidget);
    expect(find.textContaining('42:05'), findsWidgets, reason: 'duration label');
  });

  testWidgets('dragging to either end shows the ends, never an out-of-range '
      'value', (tester) async {
    await _pumpBar(tester, duration: _duration, onSeek: (_) {});

    _seekSlider(tester).onChanged!(0.0);
    await tester.pump();
    expect(find.text('00:00'), findsOneWidget);

    _sliderAt(tester, 0.0).onChanged!(1.0);
    await tester.pump();
    expect(
      find.text('42:05'),
      findsWidgets,
      reason: 'the value passed here is a fraction, so the end is the duration',
    );
  });

  testWidgets('a duration that shrinks mid-drag clamps the preview', (
    tester,
  ) async {
    await _pumpBar(tester, duration: _duration, onSeek: (_) {});
    _seekSlider(tester).onChanged!(0.9);
    await tester.pump();

    // The stream re-reports a much shorter duration while the finger is still
    // down: the stale scrub value must clamp to the new end, not print a value
    // past it.
    await _pumpBar(tester, duration: const Duration(minutes: 10), onSeek: (_) {});
    await tester.pump();
    expect(find.text('10:00'), findsOneWidget);
  });

  testWidgets('an unknown duration disables dragging and invents no preview', (
    tester,
  ) async {
    await _pumpBar(tester, duration: Duration.zero, onSeek: (_) {});

    expect(
      _sliderAt(tester, 0.0).onChanged,
      isNull,
      reason: 'without a duration there is nothing to seek within',
    );
    // The label stays the real position: zero here, NOT a scaled random value.
    expect(find.text('01:23'), findsOneWidget);
    expect(find.textContaining('00:00'), findsWidgets);
  });

  testWidgets('seeking reports the dragged position, matching the label', (
    tester,
  ) async {
    Duration? seeked;
    await _pumpBar(tester, duration: _duration, onSeek: (d) => seeked = d);

    // Hold the widget instance: once `onChanged` has run, the slider's value IS
    // the drag position, so looking it up by the resting value finds nothing.
    final slider = _seekSlider(tester);
    slider.onChanged!(0.25);
    await tester.pump();
    expect(find.text('10:31'), findsOneWidget); // 25% of 42:05

    slider.onChangeEnd!(0.25);
    await tester.pump();
    expect(seeked, const Duration(milliseconds: 631250));
    // After the seek the preview is dropped, so the label is the player's again.
    expect(find.text('01:23'), findsOneWidget);
  });

  testWidgets('the buffered indicator is dropped when nothing is buffered '
      'ahead', (tester) async {
    Future<void> pumpWith(Duration buffer) async {
      await tester.binding.setSurfaceSize(const Size(900, 240));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        _host(
          PlayerControlBar(
            playing: true,
            position: _position,
            duration: _duration,
            buffer: buffer,
            volume: 80,
            speed: 1.0,
            fullscreen: false,
            hasPrev: false,
            hasNext: false,
            hasEpisodes: false,
            onPlayPause: () {},
            onToggleMute: () {},
            onFullscreen: () {},
            onNext: () {},
            onPrev: () {},
            onEpisodes: () {},
            onSpeedChanged: (_) {},
            onSeek: (_) {},
          ),
        ),
      );
    }

    // Buffered ahead of the playhead: the secondary track is drawn.
    await pumpWith(const Duration(minutes: 10));
    expect(_seekSlider(tester).secondaryTrackValue, isNotNull);

    // Seeking into an unbuffered region reports a buffered end BEHIND the
    // position. Flutter would paint the secondary track backwards from the thumb,
    // so the bar passes null instead — the widget allows it (it only bounds the
    // value to [min, max]) and "nothing buffered ahead" is the honest reading.
    await pumpWith(const Duration(seconds: 30));
    expect(_seekSlider(tester).secondaryTrackValue, isNull);
  });

  // Regression: `onChanged`/`onChangeEnd` were the slider's only handlers, so
  // nothing told the screen that a drag had begun. Its 2s idle timer kept
  // running and faded the whole bar — the slider under the finger included —
  // out of a scrub in progress.

  testWidgets('a drag on the seek slider reports its start and its end, once '
      'each', (tester) async {
    final events = <bool>[];
    Duration? seeked;
    await _pumpBar(
      tester,
      duration: _duration,
      onSeek: (d) => seeked = d,
      onScrubActive: events.add,
    );

    // Hold the widget instance: once `onChanged` has run the slider's value IS
    // the drag position, so looking it up by the resting value finds nothing.
    final slider = _seekSlider(tester);
    slider.onChangeStart!(slider.value);
    slider.onChanged!(0.5);
    slider.onChanged!(0.75);
    await tester.pump();
    expect(
      events,
      [true],
      reason: 'the start is announced once, whatever the drag reports after it',
    );

    slider.onChangeEnd!(0.75);
    expect(events, [true, false], reason: 'exactly one end, with no repeats');
    expect(seeked, const Duration(milliseconds: 1893750));
  });

  testWidgets('a bar with no interaction listener still seeks', (tester) async {
    // The callback is optional: it stays null here and every slider handler
    // must run exactly as it did before the screen started listening.
    Duration? seeked;
    await _pumpBar(tester, duration: _duration, onSeek: (d) => seeked = d);

    final slider = _seekSlider(tester);
    slider.onChangeStart!(slider.value);
    slider.onChanged!(0.5);
    await tester.pump();
    expect(find.text('21:03'), findsOneWidget, reason: 'preview unaffected');

    slider.onChangeEnd!(0.5);
    await tester.pump();
    expect(seeked, const Duration(milliseconds: 1262500));
    expect(find.text('01:23'), findsOneWidget, reason: 'preview dropped');
  });

  testWidgets('a drag on the volume slider reports its start and its end, '
      'once each', (tester) async {
    final events = <bool>[];
    final volume = <double>[];
    await _pumpBar(
      tester,
      duration: _duration,
      onSeek: (_) {},
      onVolumeChanged: volume.add,
      onScrubActive: events.add,
    );

    // The volume slider holds the caller's value while dragging (the screen
    // writes the volume and rebuilds), so it stays findable by value.
    final slider = _volumeSlider(tester);
    slider.onChangeStart!(slider.value);
    slider.onChanged!(40);
    await tester.pump();
    expect(events, [true]);

    slider.onChangeEnd!(40);
    expect(events, [true, false]);
    expect(volume, [40]);
  });

  testWidgets('an inert volume slider announces no interaction', (tester) async {
    // No `onVolumeChanged` means no way to change the volume: the slider is
    // disabled, so it must not claim the user is interacting with it.
    final events = <bool>[];
    await _pumpBar(
      tester,
      duration: _duration,
      onSeek: (_) {},
      onScrubActive: events.add,
    );

    expect(_volumeSlider(tester).onChanged, isNull, reason: 'disabled');
    expect(_volumeSlider(tester).onChangeStart, isNull);
    expect(events, isEmpty);
  });

  testWidgets('a seek slider that cannot seek announces no interaction', (
    tester,
  ) async {
    // Zero duration is the other inert case: the bar refuses the drag, so it
    // must not tell the screen that a scrub is in progress either.
    final events = <bool>[];
    await _pumpBar(
      tester,
      duration: Duration.zero,
      onSeek: (_) {},
      onScrubActive: events.add,
    );

    expect(_sliderAt(tester, 0.0).onChangeStart, isNull);
    expect(events, isEmpty);
  });
}
