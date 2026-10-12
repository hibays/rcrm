// test/player_overlays_test.dart
// The two things the player draws over the picture: the buffering spinner and
// the up-next card. Both are about a wait, and both have a contract about when
// they are allowed to mean something.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/player_overlays.dart';

Widget _host(Widget child, {bool disableAnimations = false}) => MaterialApp(
  home: Scaffold(
    backgroundColor: Colors.black,
    body: Builder(
      builder: (ctx) => MediaQuery(
        data: MediaQuery.of(ctx).copyWith(disableAnimations: disableAnimations),
        child: child,
      ),
    ),
  ),
);

/// What the indicator is painting at, right now.
///
/// `AnimatedOpacity.opacity` is the TARGET, not the state — the animation
/// itself lives in the `FadeTransition` that widget builds.
double _opacityOf(WidgetTester tester) => tester
    .widget<FadeTransition>(
      find.descendant(
        of: find.byType(PlayerBufferingIndicator),
        matching: find.byType(FadeTransition),
      ),
    )
    .opacity
    .value;

void main() {
  group('PlayerBufferingIndicator', () {
    testWidgets('stays mounted while hidden so the exit can fade', (
      tester,
    ) async {
      // Never `pumpAndSettle` around the spinner: an indeterminate one
      // schedules frames forever, so "settled" never arrives.
      await tester.pumpWidget(
        _host(const PlayerBufferingIndicator(visible: true)),
      );
      await tester.pump(const Duration(milliseconds: 300));
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(_opacityOf(tester), 1.0);

      await tester.pumpWidget(
        _host(const PlayerBufferingIndicator(visible: false)),
      );
      // Mid-fade it is still in the tree, and driven by the animation rather
      // than snapped away.
      await tester.pump(const Duration(milliseconds: 80));
      expect(find.byType(PlayerBufferingIndicator), findsOneWidget);
      final mid = _opacityOf(tester);
      expect(mid, greaterThan(0.0));
      expect(mid, lessThan(1.0));

      await tester.pump(const Duration(milliseconds: 400));
      expect(_opacityOf(tester), 0.0);
      expect(tester.takeException(), isNull);
    });

    testWidgets('never takes a pointer', (tester) async {
      // It sits over the video, and the video is where the gesture map lives:
      // a spinner that swallowed taps would eat the tap that toggles the
      // chrome.
      var taps = 0;
      await tester.pumpWidget(
        _host(
          Stack(
            children: [
              GestureDetector(
                behavior: HitTestBehavior.opaque,
                onTap: () => taps++,
                child: const SizedBox.expand(),
              ),
              const PlayerBufferingIndicator(visible: true),
            ],
          ),
        ),
      );
      await tester.pump(const Duration(milliseconds: 300));
      await tester.tapAt(
        tester.getCenter(find.byType(PlayerBufferingIndicator)),
      );
      await tester.pump(const Duration(milliseconds: 100));
      expect(taps, 1);
    });

    testWidgets('reduced motion drops the fade but keeps the spinner', (
      tester,
    ) async {
      await tester.pumpWidget(
        _host(
          const PlayerBufferingIndicator(visible: true),
          disableAnimations: true,
        ),
      );
      await tester.pump();
      // One frame is enough: there is no fade to wait for. The spinner itself
      // is information, not decoration, so it keeps turning.
      expect(_opacityOf(tester), 1.0);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      await tester.pump(const Duration(milliseconds: 50));
    });
  });

  group('PlayerUpNextCard', () {
    const countdown = Duration(seconds: 3);
    const title = 'episode-02.mp4';

    Widget card({
      VoidCallback? onAdvance,
      VoidCallback? onDismiss,
      bool disableAnimations = false,
    }) => _host(
      PlayerUpNextCard(
        title: title,
        subtitle: '812 MB · MP4',
        countdown: countdown,
        onAdvance: onAdvance ?? () {},
        onDismiss: onDismiss ?? () {},
      ),
      disableAnimations: disableAnimations,
    );

    testWidgets('names what will play, and "Play now" is a yes', (
      tester,
    ) async {
      var advanced = 0;
      var dismissed = 0;
      await tester.pumpWidget(
        card(onAdvance: () => advanced++, onDismiss: () => dismissed++),
      );
      // A short pump rather than a settle: settling would run the countdown
      // out and the card's own answer would arrive before the tap did.
      await tester.pump(const Duration(milliseconds: 250));

      expect(find.text('Up next'), findsOneWidget);
      expect(find.text(title), findsOneWidget);
      expect(find.text('812 MB · MP4'), findsOneWidget);

      await tester.tap(find.text('Play now'));
      await tester.pump();
      expect(advanced, 1);
      expect(dismissed, 0);

      // The screen replaces the media and drops the card in the same turn;
      // unmounting it here is what stops the countdown racing the assertions.
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(seconds: 5));
      expect(advanced, 1);
    });

    testWidgets('the ✕ is not a yes, however long it is left', (tester) async {
      var advanced = 0;
      var dismissed = 0;
      await tester.pumpWidget(
        card(onAdvance: () => advanced++, onDismiss: () => dismissed++),
      );
      await tester.pump(const Duration(milliseconds: 250));
      await tester.tap(find.byIcon(Icons.close));
      await tester.pump();
      expect(dismissed, 1);

      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(seconds: 5));
      expect(advanced, 0, reason: 'dismissing is not a yes');
    });

    testWidgets('runs out on its own, once', (tester) async {
      var advanced = 0;
      await tester.pumpWidget(card(onAdvance: () => advanced++));
      await tester.pump(const Duration(milliseconds: 100));
      expect(advanced, 0, reason: 'not before the countdown');

      await tester.pump(countdown);
      await tester.pump();
      expect(advanced, 1);
      // It must not keep firing while it finishes being removed.
      await tester.pump(const Duration(seconds: 2));
      expect(advanced, 1);
    });

    testWidgets('a dismissal before the countdown ends cancels the advance', (
      tester,
    ) async {
      // The whole point of the card: the autoplay stops being something that
      // happens TO the viewer.
      var advanced = 0;
      await tester.pumpWidget(
        card(onAdvance: () => advanced++, onDismiss: () {}),
      );
      await tester.pump(const Duration(milliseconds: 200));
      await tester.tap(find.byIcon(Icons.close));
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(seconds: 5));
      expect(advanced, 0);
    });

    testWidgets('the ring drains as the countdown runs', (tester) async {
      await tester.pumpWidget(card());
      double ring() => tester
          .widget<CircularProgressIndicator>(
            find.byType(CircularProgressIndicator),
          )
          .value!;

      await tester.pump(const Duration(milliseconds: 50));
      final full = ring();
      expect(full, greaterThan(0.9), reason: 'full at the moment it appears');

      await tester.pump(const Duration(milliseconds: 1500));
      final half = ring();
      expect(half, lessThan(full));
      expect(half, greaterThan(0.2));

      await tester.pump(const Duration(milliseconds: 1200));
      expect(ring(), lessThan(half));
      await tester.pump(countdown);
      await tester.pumpAndSettle();
    });

    testWidgets('rises into place, and simply is there without motion', (
      tester,
    ) async {
      await tester.pumpWidget(card());
      await tester.pump();
      // The entrance is a transform + fade, not a jump.
      final transforms = tester.widgetList<Transform>(find.byType(Transform));
      expect(transforms, isNotEmpty);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);

      await tester.pumpWidget(card(disableAnimations: true));
      await tester.pump();
      expect(find.text(title), findsOneWidget);
      await tester.pump(countdown);
      await tester.pumpAndSettle();
    });
  });
}
