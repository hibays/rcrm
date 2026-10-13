// test/episode_picker_panel_test.dart
// How the episode sheet arrives and leaves.
//
// It was the only surface in the player with no motion at all, and the first
// entrance animation was wrong in a way only the screen could show: the scrim
// and the sheet were wrapped in ONE transform, so the full-bleed dimming layer
// travelled with the sheet and left an uncovered strip along the edge it moved
// away from — and there was no exit animation, because the sheet was unmounted
// on the tap.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/widgets/episode_picker_panel.dart';

/// Rows are not what this file is about, and a real [VideoCard] in a test
/// host brings a poster request with it (a 30s timer outlives the test) and a
/// 3px overflow at this size. The sheet's own geometry is what is under test.
const _items = <MediaItem>[];

/// Long enough to have run any of the sheet's motions to its end. Derived from
/// the constant rather than spelled out, because the duration is a design
/// decision the viewer can change: a literal 200 here would keep passing (or
/// keep failing) for reasons that have nothing to do with the behaviour under
/// test.
final _arrived = kEpisodeSheetDuration + const Duration(milliseconds: 20);

const _sheetColour = Color(0xFF1A1A1A);

/// The sheet's own container — its background is a `decoration`, not a
/// `Container.color` (that one is the scrim's).
final _sheetFinder = find.byWidgetPredicate(
  (w) =>
      w is Container &&
      w.decoration is BoxDecoration &&
      (w.decoration! as BoxDecoration).color == _sheetColour,
);

void main() {
  // Landscape: the sheet is a right-side panel, so it travels from the right.
  // `Positioned.fill` because that is how the screen puts it there — a bare
  // Stack child would be sized by the sheet itself and its list would have no
  // height to lay out in.
  Widget host(
    Widget child, {
    bool disableAnimations = false,
    Size size = const Size(1200, 800),
  }) => MaterialApp(
    home: MediaQuery(
      data: MediaQueryData(size: size).copyWith(
        disableAnimations: disableAnimations,
      ),
      child: Scaffold(
        backgroundColor: Colors.black,
        body: Stack(children: [Positioned.fill(child: child)]),
      ),
    ),
  );

  Widget panel({
    bool closing = false,
    bool still = false,
    VoidCallback? onDismiss,
  }) => host(
    EpisodePickerPanel(
      items: _items,
      onPick: (_) {},
      onDismiss: onDismiss ?? () {},
      closing: closing,
    ),
    disableAnimations: still,
  );

  /// How far the SHEET has travelled, from its own transform — the nearest
  /// ancestor Transform of the sheet's own container.
  Offset sheetOffset(WidgetTester tester) {
    final transform = tester.widget<Transform>(
      find.ancestor(of: _sheetFinder, matching: find.byType(Transform)).first,
    );
    final v = transform.transform.getTranslation();
    return Offset(v.x, v.y);
  }

  /// The scrim's alpha, and whether ANY transform sits above the layer that
  /// paints it — it must never move.
  (double alpha, bool underTransform) scrim(WidgetTester tester) {
    for (final c in tester.widgetList<Container>(find.byType(Container))) {
      final colour = c.color;
      if (colour == null || colour.a <= 0 || colour.a >= 1) continue;
      final moving = find
          .ancestor(of: find.byWidget(c), matching: find.byType(Transform))
          .evaluate()
          .isNotEmpty;
      return (colour.a, moving);
    }
    return (-1, false);
  }

  group('the episode sheet', () {
    testWidgets('arrives from the edge it is anchored to', (tester) async {
      await tester.pumpWidget(panel());
      await tester.pump(const Duration(milliseconds: 20));
      expect(
        sheetOffset(tester).dx,
        greaterThan(0),
        reason: 'starts off to the right of where it lands',
      );
      await tester.pump(_arrived);
      expect(sheetOffset(tester), Offset.zero, reason: 'arrived');
      expect(scrim(tester).$1, closeTo(0.45, 0.01));
    });

    testWidgets('the scrim FADES and never moves', (tester) async {
      // The bug: scrim and sheet in one transform, so a full-bleed dimming layer
      // travelled and left the far edge uncovered.
      await tester.pumpWidget(panel());
      await tester.pump(const Duration(milliseconds: 20));
      final (early, _) = scrim(tester);
      expect(early, lessThan(0.45), reason: 'still fading in');
      expect(
        scrim(tester).$2,
        isFalse,
        reason: 'a dimming layer must not translate',
      );
      await tester.pump(_arrived);
    });

    testWidgets('leaves the way it came, and reports when it is gone', (
      tester,
    ) async {
      var dismissed = 0;
      await tester.pumpWidget(panel(onDismiss: () => dismissed++));
      await tester.pump(_arrived);
      expect(dismissed, 0);

      // The screen flips `closing` and keeps the sheet mounted.
      await tester.pumpWidget(
        panel(closing: true, onDismiss: () => dismissed++),
      );
      await tester.pump(kEpisodeSheetDuration * 0.4);
      expect(dismissed, 0, reason: 'still on screen — it is leaving');
      expect(
        sheetOffset(tester).dx,
        greaterThan(0),
        reason: 'heading back to the right',
      );

      await tester.pump(_arrived);
      await tester.pump();
      expect(dismissed, 1, reason: 'and then it tells the screen to unmount');
    });

    testWidgets('the ✕ plays the exit too, and only once', (tester) async {
      // The ✕ and the backdrop do not go through the screen: they start the exit
      // here, so the two ways of leaving cannot disagree. The callback is called
      // directly rather than tapped, because a tap at this host's surface does
      // not land on a control the sheet positions itself near the edge of.
      var dismissed = 0;
      await tester.pumpWidget(panel(onDismiss: () => dismissed++));
      await tester.pump(_arrived);
      expect(sheetOffset(tester), Offset.zero, reason: 'arrived');

      final close = tester.widget<IconButton>(
        find.widgetWithIcon(IconButton, Icons.close),
      );
      close.onPressed!();
      // The frame a newly started animation lands on is its FIRST one, elapsed
      // zero, so the first pump only starts it ticking — the sheet must not look
      // unmounted yet, and it must not look gone either.
      await tester.pump(kEpisodeSheetDuration * 0.5);
      expect(dismissed, 0, reason: 'a press must not unmount it outright');
      // The scrim's alpha is linear in the same value the sheet's offset is, and
      // it reads the same thing: the sheet is fading back out, not sitting still.
      await tester.pump(kEpisodeSheetDuration * 0.5);
      expect(
        scrim(tester).$1,
        lessThan(0.45),
        reason: 'and it must be on its way out',
      );

      await tester.pump(_arrived);
      await tester.pump();
      expect(dismissed, 1);

      // A second press cannot start a second exit, and cannot report twice.
      close.onPressed!();
      await tester.pump(_arrived * 2);
      expect(dismissed, 1);
    });

    testWidgets('reduced motion gets the state change, not the motion', (
      tester,
    ) async {
      var dismissed = 0;
      await tester.pumpWidget(
        panel(still: true, onDismiss: () => dismissed++),
      );
      await tester.pump();
      expect(sheetOffset(tester), Offset.zero, reason: 'no travel at all');
      expect(scrim(tester).$1, closeTo(0.45, 0.01), reason: 'but fully there');

      await tester.pumpWidget(
        panel(closing: true, still: true, onDismiss: () => dismissed++),
      );
      await tester.pump();
      expect(dismissed, 1, reason: 'no animation means no waiting');
    });
  });
}