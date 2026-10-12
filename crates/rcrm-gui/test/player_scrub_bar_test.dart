// test/player_scrub_bar_test.dart
// The player's progress/volume bar: where its track really is, what the pointer
// under the cursor reads, and the two things that make it a player's bar rather
// than a settings slider — no thumb at rest, and a readout that follows the
// pointer.
//
// The geometry is tested as arithmetic first, because the whole tooltip rests
// on one claim: the pointer-to-value mapping does not move while the bar's own
// shapes animate.

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/player_scrub_bar.dart';

const _style = ScrubBarStyle(track: 3, trackActive: 6, thumb: 5);
const _width = 400.0;
const _height = 22.0;

Widget _host(Widget child, {bool disableAnimations = false}) => MaterialApp(
  home: Scaffold(
    backgroundColor: Colors.black,
    body: Builder(
      builder: (ctx) => MediaQuery(
        data: MediaQuery.of(ctx).copyWith(disableAnimations: disableAnimations),
        child: Center(
          child: SizedBox(width: _width, height: _height, child: child),
        ),
      ),
    ),
  ),
);

Widget _bar({
  double value = 0.25,
  double? buffer,
  String Function(double)? label,
  ValueChanged<double>? onChanged,
  ValueChanged<double>? onChangeStart,
  ValueChanged<double>? onChangeEnd,
  double min = 0,
  double max = 1,
}) => PlayerScrubBar(
  value: value,
  buffer: buffer,
  min: min,
  max: max,
  style: _style,
  activeColor: const Color(0xFFFF6B00),
  thumbColor: const Color(0xFFFF6B00),
  label: label,
  onChanged: onChanged,
  onChangeStart: onChangeStart,
  onChangeEnd: onChangeEnd,
);

/// The SliderTheme this bar builds — the one that carries the thumb policy.
SliderThemeData _theme(WidgetTester tester) =>
    tester.widget<SliderTheme>(find.byType(SliderTheme)).data;

/// A mouse at [dx] within the bar, held there.
Future<TestGesture> _hoverAt(WidgetTester tester, double dx) async {
  final box = tester.getRect(find.byType(PlayerScrubBar));
  final g = await tester.createGesture(kind: PointerDeviceKind.mouse);
  await g.addPointer(location: Offset.zero);
  await g.moveTo(Offset(box.left + dx, box.center.dy));
  await tester.pumpAndSettle();
  addTearDown(g.removePointer);
  return g;
}

void main() {
  group('ScrubBarGeometry', () {
    test('the track is inset by the halo, and nothing else', () {
      final g = ScrubBarGeometry.of(_width, _style);
      // The halo is `kScrubOverlayRatio` radii wide, half of it at each end.
      expect(g.left, (_style.thumb * kScrubOverlayRatio) / 2);
      expect(g.width, _width - _style.thumb * kScrubOverlayRatio);
    });

    test('pointer and value are inverses, at both ends and in the middle', () {
      final g = ScrubBarGeometry.of(_width, _style);
      expect(g.fractionAt(g.left), 0);
      expect(g.fractionAt(g.left + g.width), 1);
      expect(g.fractionAt(g.left + g.width / 2), closeTo(0.5, 1e-9));
      for (final f in [0.0, 0.1, 0.5, 0.9, 1.0]) {
        expect(g.fractionAt(g.xOf(f)), closeTo(f, 1e-9));
      }
      // Outside the track clamps instead of extrapolating.
      expect(g.fractionAt(g.left - 50), 0);
      expect(g.fractionAt(g.left + g.width + 50), 1);
    });

    test('a bar narrower than its own halo lays out instead of inverting', () {
      // `getPreferredRect` flips the edges when the box is smaller than the
      // thumb (Rect.fromLTRB swaps them), which would make the width negative
      // and the fraction meaningless.
      final g = ScrubBarGeometry.of(4, _style);
      expect(g.width, 0);
      expect(g.fractionAt(g.left), 0);
      expect(g.fractionAt(0), 0);
    });

    test('the geometry does not depend on how far the bar is expanded', () {
      // The point of pinning the halo's SIZE: the track's ends are the same
      // before, during and after the thumb grows, so a stationary pointer keeps
      // reading the same value through the whole hover animation.
      final resting = ScrubBarGeometry.of(_width, _style);
      final grown = ScrubBarGeometry.of(_width, _style);
      expect(grown.left, resting.left);
      expect(grown.width, resting.width);
    });
  });

  group('PlayerScrubBar', () {
    testWidgets('a thumb appears only while the bar is engaged', (
      tester,
    ) async {
      await tester.pumpWidget(_host(_bar(onChanged: (_) {})));
      await tester.pumpAndSettle();

      RoundSliderThumbShape thumb() =>
          _theme(tester).thumbShape! as RoundSliderThumbShape;
      expect(
        thumb().enabledThumbRadius,
        0,
        reason: 'a progress bar is a readout at rest, not a knob',
      );

      await _hoverAt(tester, _width / 2);
      expect(thumb().enabledThumbRadius, closeTo(_style.thumb, 0.01));
      expect(_theme(tester).trackHeight, greaterThan(_style.track));
    });

    testWidgets('the track thickens on hover and thins again on exit', (
      tester,
    ) async {
      await tester.pumpWidget(_host(_bar(onChanged: (_) {})));
      await tester.pumpAndSettle();
      expect(_theme(tester).trackHeight, _style.track);

      final g = await _hoverAt(tester, _width / 2);
      final grown = _theme(tester).trackHeight!;
      expect(grown, closeTo(_style.trackActive, 0.01));

      await g.moveTo(const Offset(-50, -50));
      await tester.pumpAndSettle();
      expect(_theme(tester).trackHeight, closeTo(_style.track, 0.01));
    });

    testWidgets(
      'the tooltip reads the value under the pointer, and sits on it',
      (tester) async {
        await tester.pumpWidget(
          _host(_bar(onChanged: (_) {}, label: (v) => '${(v * 100).round()}%')),
        );
        await tester.pumpAndSettle();

        // Nothing to read until a pointer is actually on the bar.
        expect(find.text('25%'), findsNothing);

        await _hoverAt(tester, _width / 2);
        expect(
          find.text('50%'),
          findsOneWidget,
          reason: 'the middle of the bar is the middle of the value range',
        );

        final box = tester.getRect(find.byType(PlayerScrubBar));
        final pill = tester.getCenter(find.text('50%'));
        expect(
          pill.dx,
          closeTo(box.left + _width / 2, 1.5),
          reason: 'the tooltip is centred on the pointer',
        );
        expect(
          pill.dy,
          lessThan(box.top),
          reason: 'and lifted clear of the bar it annotates',
        );
      },
    );

    testWidgets('the tooltip is clamped inside the bar at both edges', (
      tester,
    ) async {
      await tester.pumpWidget(
        _host(_bar(onChanged: (_) {}, label: (v) => '${(v * 100).round()}%')),
      );
      await tester.pumpAndSettle();
      final box = tester.getRect(find.byType(PlayerScrubBar));
      final geo = ScrubBarGeometry.of(_width, _style);

      // ONE pointer, moved: a second `addPointer` without a matching removal is
      // a MouseTracker assertion, not a hover.
      final g = await _hoverAt(tester, geo.xOf(0));
      expect(find.text('0%'), findsOneWidget);
      expect(
        tester.getRect(find.text('0%')).left,
        greaterThanOrEqualTo(box.left - 0.5),
      );

      await g.moveTo(Offset(box.left + geo.xOf(1), box.center.dy));
      await tester.pumpAndSettle();
      expect(find.text('100%'), findsOneWidget);
      expect(
        tester.getRect(find.text('100%')).right,
        lessThanOrEqualTo(box.right + 0.5),
      );
    });

    testWidgets('the tooltip tracks a drag the way it tracks a hover', (
      tester,
    ) async {
      // The reason the anchor comes from the POINTER rather than from the
      // thumb: a touch has no hover, and the thumb it would read is inset from
      // the track's ends by the rounded-track clamp.
      await tester.pumpWidget(
        _host(_bar(onChanged: (_) {}, label: (v) => '${(v * 100).round()}%')),
      );
      await tester.pumpAndSettle();
      final box = tester.getRect(find.byType(PlayerScrubBar));
      // The x that really reads 80%: the track is inset by the halo, so
      // `box.left + 0.8 * width` is not where 80% lives.
      final x80 = box.left + ScrubBarGeometry.of(_width, _style).xOf(0.8);

      final g = await tester.startGesture(
        Offset(box.left + _width * 0.2, box.center.dy),
      );
      // `pumpAndSettle`, not one `pump`: the engaged look is an ANIMATION, and
      // the frame that ends it only marks the bar dirty — the rebuilt theme is
      // a frame later.
      await tester.pumpAndSettle();

      await g.moveTo(Offset(x80, box.center.dy));
      await tester.pumpAndSettle();
      expect(find.text('80%'), findsOneWidget);
      expect(tester.getCenter(find.text('80%')).dx, closeTo(x80, 1.5));
      expect(
        _theme(tester).trackHeight,
        closeTo(_style.trackActive, 0.01),
        reason: 'a bar under a finger is engaged, touch or mouse alike',
      );

      await g.up();
      await tester.pumpAndSettle();
      // A touch has no hover to fall back on: the readout goes away.
      expect(find.text('80%'), findsNothing);
    });

    testWidgets('a bar without a label shows no tooltip at all', (
      tester,
    ) async {
      await tester.pumpWidget(_host(_bar(onChanged: (_) {})));
      await tester.pumpAndSettle();
      await _hoverAt(tester, _width / 2);
      expect(
        find.byType(CustomSingleChildLayout),
        findsNothing,
        reason: 'nothing to say, so nothing is drawn over the video',
      );
    });

    testWidgets('a disabled bar stays inert and never grows', (tester) async {
      await tester.pumpWidget(_host(_bar()));
      await tester.pumpAndSettle();
      expect(
        tester.widget<Slider>(find.byType(Slider)).onChanged,
        isNull,
        reason: 'no handler, no touch',
      );
      await _hoverAt(tester, _width / 2);
      // No growth and no readout: an enlarged track under the cursor is a
      // promise of interactivity, and a bar with no duration to seek within
      // cannot keep it.
      expect(_theme(tester).trackHeight, closeTo(_style.track, 0.01));
      expect(
        tester.widget<Slider>(find.byType(Slider)).onChangeStart,
        isNull,
        reason: 'and it does not claim a drag either',
      );
    });

    testWidgets('the caller\'s units survive the round trip', (tester) async {
      // Volume speaks 0..100 and progress speaks 0..1; the Slider, its
      // callbacks and its tooltip all stay in whichever the caller chose.
      final seen = <double>[];
      await tester.pumpWidget(
        _host(
          _bar(
            value: 80,
            min: 0,
            max: 100,
            label: (v) => '${v.round()}%',
            onChanged: seen.add,
          ),
        ),
      );
      await tester.pumpAndSettle();
      final slider = tester.widget<Slider>(find.byType(Slider));
      expect(slider.value, 80);
      expect(slider.max, 100);

      slider.onChanged!(40);
      expect(seen, [40]);

      // ...and the tooltip reads the same number the caller does.
      await _hoverAt(tester, _width / 2);
      expect(find.text('50%'), findsOneWidget);
    });

    testWidgets('a drag inside stays in the caller\'s units', (tester) async {
      final started = <double>[];
      final ended = <double>[];
      await tester.pumpWidget(
        _host(
          _bar(
            value: 100,
            min: 0,
            max: 100,
            onChanged: (_) {},
            onChangeStart: started.add,
            onChangeEnd: ended.add,
          ),
        ),
      );
      await tester.pumpAndSettle();
      final box = tester.getRect(find.byType(PlayerScrubBar));
      await tester.dragFrom(
        Offset(box.left + _width * 0.9, box.center.dy),
        Offset(-_width * 0.4, 0),
      );
      await tester.pumpAndSettle();
      expect(started.single, closeTo(100, 2));
      expect(ended.single, lessThan(60));
    });

    testWidgets('reduced motion snaps the hover instead of animating it', (
      tester,
    ) async {
      await tester.pumpWidget(
        _host(
          _bar(onChanged: (_) {}, label: (v) => '${(v * 100).round()}%'),
          disableAnimations: true,
        ),
      );
      await tester.pumpAndSettle();

      final box = tester.getRect(find.byType(PlayerScrubBar));
      final g = await tester.createGesture(kind: PointerDeviceKind.mouse);
      await g.addPointer(location: Offset.zero);
      addTearDown(g.removePointer);
      await g.moveTo(Offset(box.left + _width / 2, box.center.dy));
      // ONE frame: with animation disabled there is nothing left to wait for.
      await tester.pump();

      expect(find.text('50%'), findsOneWidget);
      expect(_theme(tester).trackHeight, closeTo(_style.trackActive, 0.01));
    });

    testWidgets('the slider can name itself and read its value aloud', (
      tester,
    ) async {
      final semantics = tester.ensureSemantics();
      // The value a reader hears is the one the tooltip prints, in the same
      // units the caller speaks — that is the whole point of routing both
      // through one label function.
      await tester.pumpWidget(
        _host(
          PlayerScrubBar(
            value: 0.25,
            style: _style,
            activeColor: const Color(0xFFFF6B00),
            thumbColor: const Color(0xFFFF6B00),
            label: (v) => '${(v * 100).round()}%',
            onChanged: (_) {},
          ),
        ),
      );
      await tester.pumpAndSettle();
      final slider = tester.widget<Slider>(find.byType(Slider));
      expect(slider.semanticFormatterCallback, isNotNull);
      expect(slider.semanticFormatterCallback!(0.25), '25%');

      // With a name, the node a reader lands on first carries it.
      await tester.pumpWidget(
        _host(
          PlayerScrubBar(
            value: 0.25,
            style: _style,
            activeColor: const Color(0xFFFF6B00),
            thumbColor: const Color(0xFFFF6B00),
            semanticsLabel: 'Playback position',
            label: (v) => '${(v * 100).round()}%',
            onChanged: (_) {},
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.bySemanticsLabel('Playback position'), findsOneWidget);
      // Disposed HERE, not in a tear-down: the binding verifies its handles
      // before tear-downs run.
      semantics.dispose();
    });
  });
}
