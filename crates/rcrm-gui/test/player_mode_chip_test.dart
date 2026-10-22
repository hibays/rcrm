// test/player_mode_chip_test.dart
// The playback mode, as the transport bar's own chip: what it reports, what it
// offers, and where it refuses to offer anything.
//
// This is where the settings panel's mode tests went. The row moved to the bar
// (`utils/player_playback_mode.dart` explains why), and the property those tests
// pinned travelled with it: every mode says what it will really do. It is now
// stronger than it was — four modes carry four sentences at once, in the menu,
// instead of one sentence describing whichever mode happened to be selected.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/utils/player_playback_mode.dart';
import 'package:rcrm_gui/widgets/player_controls.dart';

/// Wide enough that the plan admits every control — including the chip under
/// test, which is the last of the ordinary ones to be admitted.
const _wide = Size(1280, 720);

Future<void> _pumpBar(
  WidgetTester tester, {
  PlaybackMode mode = PlaybackMode.pauseAfter,
  ValueChanged<PlaybackMode>? onModeChanged,
  Size size = _wide,
}) async {
  // Through the VIEW, not `setSurfaceSize`: the bar reads `MediaQuery.sizeOf`,
  // which follows the view, so a surface-only size leaves it planning the
  // density tier of the default 800x600 window at every size in this file.
  await tester.pumpWidget(const SizedBox());
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(() {
    tester.view.reset();
  });
  await tester.pumpWidget(
    MaterialApp(
      home: Scaffold(
        backgroundColor: Colors.black,
        body: Stack(
          children: [
            Positioned(
              left: 0,
              right: 0,
              bottom: 0,
              child: PlayerControlBar(
                playing: true,
                position: const Duration(minutes: 1),
                duration: const Duration(minutes: 42),
                buffer: const Duration(minutes: 2),
                volume: 80,
                speed: 1.0,
                mode: mode,
                fullscreen: false,
                hasPrev: true,
                hasNext: true,
                onModeChanged: onModeChanged,
                onPlayPause: () {},
                onToggleMute: () {},
                onSeek: (_) {},
              ),
            ),
          ],
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _openMenu(WidgetTester tester) async {
  await tester.tap(find.byKey(const ValueKey('mode_chip')));
  await tester.pumpAndSettle();
}

/// Dismisses an open menu the way a viewer does — a tap on the barrier, which is
/// also what the next case needs: `pumpWidget` updates the same Navigator, so a
/// menu left open would swallow the next `_openMenu`'s tap as a dismiss.
Future<void> _dismissMenu(WidgetTester tester) async {
  await tester.tapAt(const Offset(4, 4));
  await tester.pumpAndSettle();
}

/// WCAG contrast of two opaque colors, so "readable in a dim room" is a number
/// rather than an opinion.
double _contrast(Color a, Color b) {
  final la = a.computeLuminance(), lb = b.computeLuminance();
  final hi = la > lb ? la : lb, lo = la > lb ? lb : la;
  return (hi + 0.05) / (lo + 0.05);
}

Color _chipColor(WidgetTester tester) {
  final box = tester.widget<Container>(
    find.byKey(const ValueKey('mode_chip')),
  );
  return (box.decoration! as BoxDecoration).color!;
}

void main() {
  testWidgets('every mode says what it will really do, in the menu', (
    tester,
  ) async {
    // "Loop All" and "Loop One" are one letter apart and mean opposite things,
    // and neither says that the next video arrives through a countdown the
    // viewer can refuse — none of which a two-word label can carry.
    await _pumpBar(tester, onModeChanged: (_) {});
    await _openMenu(tester);
    for (final mode in PlaybackMode.values) {
      expect(find.text(mode.label), findsOneWidget, reason: mode.label);
      expect(
        find.text(mode.note),
        findsOneWidget,
        reason: '${mode.label} explains itself, where it is chosen',
      );
    }
    // The sentences themselves: the two offering modes differ in exactly one
    // word, and that word is the whole difference between them. They are also
    // ONE LINE — the menu was a wall of text at two lines a row, and the length
    // is what keeps it a menu. (32 characters is the budget a 300dp menu row
    // gives an 11dp note after its glyph; the renders check the wrap, this
    // checks the copy cannot grow back into paragraphs.)
    expect(PlaybackMode.loopAll.note, contains('Next video in Related'));
    expect(PlaybackMode.shuffle.note, contains('Random video in Related'));
    expect(PlaybackMode.loopOne.note, contains('Replay'));
    expect(PlaybackMode.pauseAfter.note, contains('last frame'));
    for (final mode in PlaybackMode.values) {
      expect(
        mode.note.length,
        lessThanOrEqualTo(32),
        reason: '${mode.label}\'s sentence grew back into a paragraph',
      );
    }
  });

  testWidgets('picking a mode hands it back', (tester) async {
    final picked = <PlaybackMode>[];
    await _pumpBar(tester, onModeChanged: picked.add);
    await _openMenu(tester);
    await tester.tap(find.text('Loop One'));
    await tester.pumpAndSettle();
    expect(picked, [PlaybackMode.loopOne]);
  });

  testWidgets('the chip reports the mode in force, closed', (tester) async {
    // The glyph is the report: one glance, no menu. This is also the tree-shaking
    // guard — a glyph looked up at runtime would render an empty box, and
    // `find.byIcon` would find nothing.
    const expected = {
      PlaybackMode.loopAll: Icons.repeat,
      PlaybackMode.shuffle: Icons.shuffle,
      PlaybackMode.loopOne: Icons.repeat_one,
      PlaybackMode.pauseAfter: Icons.stop_circle_outlined,
    };
    for (final mode in PlaybackMode.values) {
      await _pumpBar(tester, mode: mode);
      expect(
        find.byIcon(expected[mode]!),
        findsOneWidget,
        reason: '${mode.label} is answerable from across the room',
      );
      // The tooltip names the STATE, not the control: "Playback mode" would
      // have made a screen reader announce a category and a glyph.
      expect(
        find.byTooltip('When the video ends: ${mode.label}'),
        findsOneWidget,
        reason: '${mode.label} has no name for a reader who cannot see it',
      );
    }
  });

  testWidgets('the pill is small; the target is not', (tester) async {
    // The chip measured 23x21 while every other control in the bar is 40x40:
    // `PopupMenuButton` adds no padding around its child, so the pill WAS the
    // target. The face stays a glyph in a pill; the box around it is the bar's
    // own height and 80% of its width (see `modeChipWidth` for the 80%).
    // 375, not 360: the test font is one em per character, which makes the
    // time readout ~2.5x its real width, and at 360 that budget pushes the chip
    // out of the plan. 375 is the narrowest width where this test host can see
    // the chip at all; the render harness (real Roboto) covers 360.
    await _pumpBar(
      tester,
      size: const Size(375, 667),
      onModeChanged: (_) {},
    );
    final face = tester.getSize(find.byKey(const ValueKey('mode_chip')));
    final target = tester.getSize(
      find.byType(PopupMenuButton<PlaybackMode>),
    );
    expect(target, const Size(32, 40), reason: 'compact: 32x40, not 24x24');
    expect(face.width, lessThan(target.width));
    expect(face.height, lessThan(target.height));

    await _pumpBar(
      tester,
      size: const Size(1280, 720),
      onModeChanged: (_) {},
    );
    expect(
      tester.getSize(find.byType(PopupMenuButton<PlaybackMode>)),
      const Size(41, 44),
      reason: 'expanded: the pill is wide enough to be its own target',
    );
  });

  testWidgets('the accent follows the state, not the selection', (tester) async {
    // Same rule as the speed chip beside it: a state other than the ordinary one
    // is worth an accent. `pauseAfter` is the app's default, so it is the one
    // that stays quiet.
    await _pumpBar(tester, mode: PlaybackMode.pauseAfter);
    expect(_chipColor(tester), Colors.white.withValues(alpha: 0.08));

    await _pumpBar(tester, mode: PlaybackMode.loopOne);
    expect(_chipColor(tester), RCrmColors.primary.withValues(alpha: 0.16));

    await _pumpBar(tester, mode: PlaybackMode.shuffle);
    expect(_chipColor(tester), RCrmColors.primary.withValues(alpha: 0.16));
  });

  testWidgets('with nothing to change it, the chip is a report only', (
    tester,
  ) async {
    // A control that opens a menu it cannot act on is the dead-control defect:
    // no handler means no menu, and no affordance claiming one.
    await _pumpBar(tester);
    await _openMenu(tester);
    expect(find.text(PlaybackMode.loopOne.label), findsNothing);
    expect(find.byKey(const ValueKey('mode_chip')), findsOneWidget);
  });

  testWidgets('the menu fits the smallest surfaces, notes and all', (
    tester,
  ) async {
    // The menu is an overlay, so it does not compete with the bar for width —
    // but its sentences are long, and a menu wider than the screen is a menu
    // whose choices cannot be read. Landscape phone and portrait phone.
    for (final size in [const Size(640, 360), const Size(360, 640)]) {
      await _pumpBar(tester, size: size, onModeChanged: (_) {});
      // The bar may have dropped the chip at this width; drive the menu through
      // it only where it is really there.
      if (find.byKey(const ValueKey('mode_chip')).evaluate().isEmpty) {
        continue;
      }
      await _openMenu(tester);
      expect(
        tester.takeException(),
        isNull,
        reason: 'the menu overflowed at $size',
      );
      expect(find.text(PlaybackMode.pauseAfter.note), findsOneWidget);
      // Four one-line notes, four rows: the menu that carried a paragraph per
      // mode measured ~350dp here (and 480 at 1.6x). This is the test-font
      // height, so it is a ceiling rather than a number the phone paints.
      final rows = find.byType(PopupMenuItem<PlaybackMode>);
      final menu =
          tester.getRect(rows.last).bottom -
          tester.getRect(rows.first).top +
          16; // the menu's own 8dp top and bottom padding
      expect(
        menu,
        lessThan(300),
        reason: 'the menu grew back into a panel at $size',
      );
      await _dismissMenu(tester);
    }
  });

  testWidgets('a note is readable in a dim room, not decorative gray', (
    tester,
  ) async {
    // The sentences are the whole reason the menu carries text, and they shipped
    // at `white38` — 3.6:1 on Ash, below AA for an 11dp line, and exactly the
    // washed-out gray the system bans ("Silver is silver, not ash"). Readability
    // in dim light is this product's stated accessibility goal, so the floor is
    // asserted rather than eyeballed.
    await _pumpBar(tester, onModeChanged: (_) {});
    await _openMenu(tester);
    for (final mode in PlaybackMode.values) {
      final style = tester.widget<Text>(find.text(mode.note)).style!;
      expect(
        _contrast(style.color!, RCrmColors.ash),
        greaterThanOrEqualTo(4.5),
        reason: '${mode.label} is explained in text nobody can read',
      );
    }
    await _dismissMenu(tester);
  });

  testWidgets('the upward offset is the menu\'s real height, at every text scale', (
    tester,
  ) async {
    // The menu opens by a NEGATIVE offset, so its own height decides where it
    // lands — and `PopupMenuItem.height` is a minimum, not a height: a row is 78dp
    // at 1.0x text and 139dp at 1.6x with the app's own font. An offset computed
    // from the nominal row therefore lands the last row on top of the very chip
    // that opened it, at exactly the sizes where the text is hardest to read.
    //
    // The invariant is the offset itself, not the painted position: on a window
    // shorter than the menu there is nowhere for the menu to go, and the framework
    // clamps it to the screen (see the note below). Asserting the offset against
    // the height the rows REALLY take is font-independent and is the property that
    // keeps "clear of the bar" true wherever there is room for it.
    for (final scale in [1.0, 1.3, 1.6]) {
      tester.platformDispatcher.textScaleFactorTestValue = scale;
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      await _pumpBar(tester, onModeChanged: (_) {});
      final offset =
          tester
              .widget<PopupMenuButton<PlaybackMode>>(
                find.byType(PopupMenuButton<PlaybackMode>),
              )
              .offset
              .dy;
      await _openMenu(tester);
      final rows = find.byType(PopupMenuItem<PlaybackMode>);
      final painted =
          tester.getRect(rows.last).bottom -
          tester.getRect(rows.first).top +
          16; // the menu's own 8dp top and bottom padding
      expect(
        -offset,
        moreOrLessEquals(painted, epsilon: 0.5),
        reason: 'the menu opens by its nominal height, not its real one',
      );
      await _dismissMenu(tester);
    }
  });

  testWidgets('where there is room, the menu clears the bar', (tester) async {
    // The painted half of the same promise, asserted only where it is physically
    // possible: the bar sits at the bottom of the window, so a menu taller than
    // the space above it has nowhere to be except over the bar. At 1.3x the
    // window is still tall enough; the offset is what buys that (see above).
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    await _pumpBar(tester, onModeChanged: (_) {});
    await _openMenu(tester);
    final chip = tester.getRect(find.byKey(const ValueKey('mode_chip')));
    final menuBottom = tester
        .getRect(find.byType(PopupMenuItem<PlaybackMode>).last)
        .bottom;
    expect(
      menuBottom,
      lessThanOrEqualTo(chip.top),
      reason: 'the menu covered the chip that opened it',
    );
    await _dismissMenu(tester);
  });

  testWidgets('a row keeps room around its sentence once it outgrows the floor', (
    tester,
  ) async {
    // Material 3 hands a menu item no vertical padding at all, so a row whose
    // note wraps past the nominal height grows into its neighbour and four
    // choices read as one paragraph. The floor and the breathing are two jobs.
    tester.platformDispatcher.textScaleFactorTestValue = 1.6;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    await _pumpBar(tester, onModeChanged: (_) {});
    await _openMenu(tester);
    for (final mode in PlaybackMode.values) {
      final row = tester.getRect(
        find.ancestor(
          of: find.text(mode.note),
          matching: find.byType(PopupMenuItem<PlaybackMode>),
        ),
      );
      final label = tester.getRect(find.text(mode.label));
      final note = tester.getRect(find.text(mode.note));
      expect(
        label.top - row.top,
        greaterThanOrEqualTo(4),
        reason: '${mode.label} has no air above it at 1.6x',
      );
      expect(
        row.bottom - note.bottom,
        greaterThanOrEqualTo(4),
        reason: '${mode.label} sits on the next row at 1.6x',
      );
    }
    await _dismissMenu(tester);
  });
}
