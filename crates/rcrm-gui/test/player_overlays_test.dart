// test/player_overlays_test.dart
// The two things the player draws over the picture while it waits or fails:
// the buffering spinner and the playback-error card.

import 'package:material_ui/material_ui.dart';
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

  group('PlayerPlaybackError', () {
    testWidgets('shows the player message and both exits', (tester) async {
      var retried = 0;
      var backed = 0;
      await tester.pumpWidget(
        _host(
          PlayerPlaybackError(
            message: 'Failed to open: HTTP 404 Not Found',
            onRetry: () => retried++,
            onBack: () => backed++,
          ),
        ),
      );

      expect(find.text("Can't play this video"), findsOneWidget);
      expect(find.text('Failed to open: HTTP 404 Not Found'), findsOneWidget);

      await tester.tap(find.text('Try again'));
      await tester.pump();
      expect(retried, 1);

      await tester.tap(find.text('Back'));
      await tester.pump();
      expect(backed, 1);
    });

    testWidgets('bounds a long player message to four lines', (tester) async {
      final long = 'x' * 1000;
      await tester.pumpWidget(
        _host(
          PlayerPlaybackError(message: long, onRetry: () {}, onBack: () {}),
        ),
      );

      final text = tester.widget<Text>(find.text(long));
      expect(text.maxLines, 4);
      expect(text.overflow, TextOverflow.ellipsis);
    });

    testWidgets('a tap on the card does not reach the player underneath', (
      tester,
    ) async {
      var playerTaps = 0;
      await tester.pumpWidget(
        _host(
          Stack(
            children: [
              GestureDetector(
                behavior: HitTestBehavior.opaque,
                onTap: () => playerTaps++,
                child: const SizedBox.expand(),
              ),
              PlayerPlaybackError(
                message: 'HTTP 404',
                onRetry: () {},
                onBack: () {},
              ),
            ],
          ),
        ),
      );

      await tester.tapAt(tester.getCenter(find.byType(PlayerPlaybackError)));
      await tester.pump();
      expect(playerTaps, 0);
    });
  });
}
