// test/player_control_layout_test.dart
// Width-budget rules for the player control bar.
//
// The bar used to decide with one boolean (maxWidth < 400) and then hide
// whole groups of controls; it overflowed whenever a fullscreen "scale" made
// the row wider than the device. These tests pin the replacement contract:
// the plan always fits, essentials never disappear, and the volume slider is
// the first thing to go — keeping its mute button.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/player_controls.dart';

/// Approximate painted widths, measured from the real styles in the bar.
const posW = 32.0;
const durW = 40.0;
const speedW = 40.0;

PlayerControlPlan plan(
  double width, {
  bool fullscreen = false,
  bool hasPrev = true,
  bool hasNext = true,
  bool? hasEpisodes,
  Size? window,
}) {
  // A landscape phone is 640x360: the shortest side picks the density.
  final win = window ?? Size(width, fullscreen ? 360 : 800);
  final m = PlayerChromeMetrics.of(win, fullscreen: fullscreen).cappedTo(width);
  return planPlayerControlBar(
    maxWidth: width,
    m: m,
    positionWidth: posW,
    durationWidth: durW,
    speedWidth: speedW,
    // The mode chip is an icon in a padded box and its width is DERIVED from the
    // metrics, not measured text — so the test can use the real formula rather
    // than a stand-in (about 23dp compact, 40dp expanded).
    modeWidth: m.modeChipWidth,
    hasPrev: hasPrev,
    hasNext: hasNext,
    // The episode sheet only exists in fullscreen, so the windowed bar never
    // spends width on its button.
    hasEpisodes: hasEpisodes ?? fullscreen,
  );
}

void main() {
  group('planPlayerControlBar', () {
    test('never exceeds the width it was given (40..2000dp)', () {
      // Starts at 40dp: below ~108dp the ladder drops the fullscreen button and
      // below ~74dp it drops mute, and those two branches used to be outside this
      // invariant entirely. 40dp is the *measured* structural floor — widening
      // this loop downward found that even with every optional control dropped
      // the bar still needs 40dp (play/pause plus its own gaps and padding), so a
      // narrower window is not a case the planner can serve at all.
      for (var w = 40.0; w <= 2000; w += 1) {
        for (final fs in [false, true]) {
          final p = plan(w, fullscreen: fs);
          expect(
            p.contentWidth,
            lessThanOrEqualTo(w + 0.001),
            reason: 'overflow at ${w}dp (fullscreen: $fs): $p',
          );
        }
      }
    });

    test('a dropped control never comes back as the bar gets narrower', () {
      // Monotone ladder: once fullscreen (then mute) is gone at some width, no
      // narrower width may show it again — otherwise the bar would flicker while
      // a window is dragged, and the drop order would not be a ladder at all.
      var sawFullscreen = true;
      var sawMute = true;
      var sawMode = true;
      for (var w = 2000.0; w >= 40; w -= 1) {
        final p = plan(w);
        if (!sawFullscreen) {
          expect(
            p.showFullscreen,
            isFalse,
            reason: 'fullscreen returned at ${w}dp',
          );
        }
        if (!sawMute) {
          expect(p.showMute, isFalse, reason: 'mute returned at ${w}dp');
        }
        if (!sawMode) {
          expect(p.showMode, isFalse, reason: 'the mode chip returned at ${w}dp');
        }
        sawFullscreen = sawFullscreen && p.showFullscreen;
        sawMute = sawMute && p.showMute;
        sawMode = sawMode && p.showMode;
      }
    });

    test('the narrowest bar keeps its three essentials and fits', () {
      // Below the compact floor (140dp) the tier shrinks once instead of
      // overflowing: no minimum window size is set, so a desktop window can
      // really be dragged this narrow.
      final p = plan(120, window: const Size(120, 500));
      expect(p.contentWidth, lessThanOrEqualTo(120));
      expect(p.showVolumeSlider, isFalse);
      expect(p.showPosition, isFalse);
      expect(p.showDuration, isFalse);
      expect(p.showNext, isFalse);
      expect(p.showPrev, isFalse);
      expect(p.showSpeed, isFalse);
    });

    test('portrait phone (360dp): no volume slider, mute button stays', () {
      final p = plan(360, window: const Size(360, 800));
      expect(p.showVolumeSlider, isFalse);
      expect(p.showPosition, isTrue);
      expect(
        p.showNext,
        isTrue,
        reason: 'skipping an episode must stay one tap',
      );
      expect(p.contentWidth, lessThanOrEqualTo(360));
    });

    test('the slider appears exactly when the rest leaves it room', () {
      // 411dp: time, skip and rate are all still shown, so there is no room
      // left for a draggable slider — the mute button carries volume alone.
      expect(plan(411, window: const Size(411, 900)).showVolumeSlider, isFalse);
      // The mode chip took the slider's next doorway: it is admitted BEFORE the
      // slider's leftover is measured, so at 440dp the bar spends those 30dp on
      // the chip and the slider is gone (mute, the wheel, the volume gestures
      // and the hardware keys all still move the volume — which is the whole
      // reason the slider is the last thing admitted). Where the chip's removal
      // would leave the mode unreachable, the slider is the one that yields:
      // there is no other door to the mode at all, and a setting nobody can
      // reach is the worse trade. Pinned in both directions below.
      final chipNotSlider = plan(440, window: const Size(440, 900));
      expect(chipNotSlider.showMode, isTrue, reason: 'the new chip is admitted');
      expect(chipNotSlider.showVolumeSlider, isFalse);
      expect(chipNotSlider.contentWidth, lessThanOrEqualTo(440));
      // A little wider and the slider earns its minimum drag width as well...
      final wider = plan(470, window: const Size(470, 900));
      expect(wider.showVolumeSlider, isTrue);
      expect(wider.showMode, isTrue, reason: 'and the chip keeps its place');
      expect(
        wider.volumeSliderWidth,
        greaterThanOrEqualTo(kMinVolumeSliderWidth),
      );
      expect(wider.contentWidth, lessThanOrEqualTo(470));
      // ...without ever costing the controls that have no alternative.
      expect(wider.showPrev, isTrue);
      expect(wider.showNext, isTrue);
      expect(wider.showSpeed, isTrue);
    });
    test('landscape phone fullscreen (640x360) fits everything', () {
      final p = plan(640, fullscreen: true, window: const Size(640, 360));
      expect(p.showVolumeSlider, isTrue);
      expect(p.showSpeed, isTrue);
      expect(p.showEpisodes, isTrue);
      expect(p.showPrev, isTrue);
      expect(p.contentWidth, lessThanOrEqualTo(640));
    });

    test('desktop fullscreen gives the slider its full width', () {
      final p = plan(1920, fullscreen: true, window: const Size(1920, 1080));
      expect(
        p.volumeSliderWidth,
        PlayerChromeMetrics.expandedFullscreen.volumeSliderMax,
      );
      expect(p.contentWidth, lessThanOrEqualTo(1920));
    });

    test('very narrow: optional controls yield, essentials never do', () {
      final p = plan(250, window: const Size(250, 500));
      final m = PlayerChromeMetrics.of(const Size(250, 500)).cappedTo(250);
      expect(p.showVolumeSlider, isFalse);
      expect(p.showSpeed, isFalse);
      expect(p.showNext, isFalse);
      // Play/pause, mute and fullscreen are unconditional: the bar always
      // reserves their three tap targets.
      expect(p.contentWidth, greaterThanOrEqualTo(m.tap * 3));
      expect(p.contentWidth, lessThanOrEqualTo(250));
    });

    test('optional controls are never dropped while they still fit', () {
      var lastShown = -1;
      for (var w = 240.0; w <= 1400; w += 4) {
        final p = plan(w, fullscreen: true);
        final shown = [
          p.showPosition,
          p.showDuration,
          p.showNext,
          p.showPrev,
          p.showSpeed,
          p.showEpisodes,
          p.showMode,
        ].where((e) => e).length;
        expect(
          shown,
          greaterThanOrEqualTo(lastShown),
          reason: 'a wider bar dropped a control at ${w}dp: $p',
        );
        lastShown = shown;
      }
    });

    test('absent neighbours are never planned', () {
      // Presence follows availability, so a skip button the user can see is
      // always one they can press. The cost — the row reflows once, when the
      // jump history first becomes non-empty — is the accepted one.
      final p = plan(1920, hasPrev: false, hasNext: false, hasEpisodes: false);
      expect(p.showPrev, isFalse);
      expect(p.showNext, isFalse);
      expect(p.showEpisodes, isFalse);
    });

    test('density follows the bar width, not the window behind it', () {
      // Desktop window, but the bar only got 470dp (side-by-side layout).
      final inWideWindow = plan(470, window: const Size(1600, 900));
      final inNarrowWindow = plan(470, window: const Size(470, 900));
      expect(inWideWindow.contentWidth, inNarrowWindow.contentWidth);
      expect(inWideWindow.volumeSliderWidth, inNarrowWindow.volumeSliderWidth);
    });
  });

  group('PlayerChromeMetrics', () {
    test('size classes follow the shortest side, not the device', () {
      expect(
        PlayerChromeMetrics.of(const Size(640, 360)),
        PlayerChromeMetrics.compact,
      );
      expect(
        PlayerChromeMetrics.of(const Size(411, 900)),
        PlayerChromeMetrics.regular,
      );
      expect(
        PlayerChromeMetrics.of(const Size(1600, 900)),
        PlayerChromeMetrics.expanded,
      );
      expect(
        PlayerChromeMetrics.of(const Size(1920, 1080), fullscreen: true),
        PlayerChromeMetrics.expandedFullscreen,
      );
    });

    test('a bar below the compact floor drops to the tiny tier', () {
      expect(
        PlayerChromeMetrics.expanded.cappedTo(139),
        PlayerChromeMetrics.tiny,
      );
      expect(
        PlayerChromeMetrics.expanded.cappedTo(140),
        PlayerChromeMetrics.compact,
      );
      // The tier the plan then uses really does fit its essentials.
      final floor =
          3 * PlayerChromeMetrics.tiny.tap +
          2 * PlayerChromeMetrics.tiny.gap +
          2 * PlayerChromeMetrics.tiny.pad;
      expect(floor, lessThanOrEqualTo(140));
    });

    test('fullscreen never inflates the compact tier', () {
      // The old bar scaled every control by 1.3 in fullscreen — on exactly the
      // device with the least width per dp. Density only ever follows width.
      expect(
        PlayerChromeMetrics.of(const Size(640, 360), fullscreen: true),
        PlayerChromeMetrics.compact,
      );
    });
  });
}
