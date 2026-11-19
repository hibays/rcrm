// test/settings_appearance_test.dart
// Appearance: System / Day / Night and the five preset accents.
//
// What is pinned here: both values round-trip through SharedPreferences with a
// whitelist on the read side; Day and Night really build different canvases and
// the accent deepens on cream; the runtime RCrmColors snapshot flips every ramp
// step; and the Settings row writes through on the same frame, with no restart.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';

/// WCAG contrast of two opaque colours, so "readable" is a number rather than
/// an opinion.
double _contrast(Color a, Color b) {
  final la = a.computeLuminance(), lb = b.computeLuminance();
  final hi = la > lb ? la : lb, lo = la > lb ? lb : la;
  return (hi + 0.05) / (lo + 0.05);
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  tearDown(() {
    // The palette is a process-wide snapshot; leave it as a fresh Night app
    // would find it so other tests in this file cannot inherit a Day ramp.
    RCrmColors.setSystemColors();
    RCrmColors.setCustomColor(null);
    RCrmColors.apply(accent: RCrmAccent.marquee, brightness: Brightness.dark);
  });

  test(
    'appearance mode round-trips, default SYSTEM, unknown falls back',
    () async {
      final s = SettingsService();
      expect(await s.getAppearanceMode(), 'system');

      for (final mode in ['day', 'night', 'system']) {
        await s.setAppearanceMode(mode);
        expect(await s.getAppearanceMode(), mode);
      }
      await s.setAppearanceMode('garbage');
      expect(
        await s.getAppearanceMode(),
        'system',
        reason:
            'a preference file this build did not write cannot invent a mode',
      );
    },
  );

  test(
    'accent round-trips, default Marquee, unknown resolves at the consumer',
    () async {
      final s = SettingsService();
      expect(await s.getAppearanceAccent(), 'marquee');

      await s.setAppearanceAccent('neon');
      expect(await s.getAppearanceAccent(), 'neon');
      expect(RCrmAccent.fromKey('neon'), RCrmAccent.neon);
      expect(RCrmAccent.fromKey('garbage'), RCrmAccent.marquee);
      expect(RCrmAccent.fromKey(null), RCrmAccent.marquee);
    },
  );

  test('six presets + Custom, distinct stable keys (incl. Material You)', () {
    final presets = RCrmAccent.values.where((a) => a != RCrmAccent.custom);
    expect(presets, hasLength(6));
    expect(presets.map((a) => a.key).toSet(), hasLength(6));
    expect(presets.map((a) => a.dark).toSet(), hasLength(6));
    expect(presets.map((a) => a.light).toSet(), hasLength(6));
    expect(RCrmAccent.values, hasLength(7));
    expect(RCrmAccent.fromKey('custom'), RCrmAccent.custom);
  });

  test('the picked colour round-trips and survives switching to a preset', () async {
    final s = SettingsService();
    expect(await s.getAppearanceCustomColor(), isNull);
    await s.setAppearanceCustomColor(0xFF3366FF);
    expect(await s.getAppearanceCustomColor(), 0xFF3366FF);
    // Accent and colour are two doors, not one: a preset switch keeps the pick.
    await s.setAppearanceAccent('neon');
    expect(await s.getAppearanceAccent(), 'neon');
    expect(await s.getAppearanceCustomColor(), 0xFF3366FF);
  });

  test('a picked colour is contrast-checked on both canvases', () {
    // The picker allows anything, including white, black and pale washes. None
    // of them may make an action or an icon unreadable on either appearance.
    for (final picked in <Color>[
      const Color(0xFFFFFFFF),
      const Color(0xFF000000),
      const Color(0xFFFFF9C4), // pale yellow
      const Color(0xFF101D5A), // near-black blue
      const Color(0xFF3366FF),
      const Color(0xFF00D9C0),
    ]) {
      RCrmColors.setCustomColor(picked);
      final night = RCrmTheme.customDark(picked);
      final day = RCrmTheme.customLight(picked);
      expect(night.a, 1.0, reason: 'a theme colour is always opaque');
      expect(day.a, 1.0, reason: 'a theme colour is always opaque');
      expect(
        _contrast(night, RCrmColors.darkPitch),
        greaterThanOrEqualTo(4.5),
        reason: 'Night shade of ${picked.toARGB32()} must read on pitch',
      );
      expect(
        _contrast(day, RCrmColors.lightPitch),
        greaterThanOrEqualTo(4.5),
        reason: 'Day shade of ${picked.toARGB32()} must read on cream',
      );
      // The card step is the extreme of each neutral ramp: if the accent reads
      // there, it reads on the canvas and ash between them too.
      expect(
        _contrast(night, RCrmColors.darkChar),
        greaterThanOrEqualTo(4.5),
        reason: 'Night shade of ${picked.toARGB32()} must read on a card too',
      );
      expect(
        _contrast(day, RCrmColors.lightChar),
        greaterThanOrEqualTo(4.5),
        reason: 'Day shade of ${picked.toARGB32()} must read on a card too',
      );
      // ThemeData and the runtime snapshot derive from the one same function.
      expect(
        RCrmTheme.build(
          accent: RCrmAccent.custom,
          brightness: Brightness.dark,
        ).colorScheme.primary,
        night,
      );
      expect(
        RCrmTheme.build(
          accent: RCrmAccent.custom,
          brightness: Brightness.light,
        ).colorScheme.primary,
        day,
      );
      // onPrimary is measured for a picked hue, never assumed.
      expect(
        RCrmTheme.onPrimaryFor(RCrmAccent.custom, Brightness.dark, night),
        night.computeLuminance() > 0.5
            ? const Color(0xFF101010)
            : const Color(0xFFFFFFFF),
      );
      // Player chrome always carries the bright Night variant.
      RCrmColors.apply(accent: RCrmAccent.custom, brightness: Brightness.light);
      expect(RCrmColors.playerAccent, night);
    }
    RCrmColors.setCustomColor(null);
  });

  test('Material You uses the OS colour, and hides itself when there is none', () {
    const wallpaperLight = Color(0xFF3F51B5);
    const wallpaperDark = Color(0xFFB0BEC5);
    expect(RCrmColors.hasSystemColor, isFalse);
    expect(
      RCrmTheme.primaryFor(RCrmAccent.materialYou, Brightness.light),
      RCrmAccent.materialYou.light,
      reason: 'no OS scheme -> neutral fallback, and the swatch is hidden',
    );

    RCrmColors.setSystemColors(light: wallpaperLight, dark: wallpaperDark);
    // `hasSystemColor` is Android-only on purpose (dynamic_color also offers a
    // desktop accent, which would let the OS blue replace the brand). This
    // host is desktop, so the gate stays closed even with colours supplied —
    // the Android half is device-verified, not covered here.
    expect(RCrmColors.hasSystemColor, isFalse);
    expect(
      RCrmTheme.primaryFor(RCrmAccent.materialYou, Brightness.light),
      wallpaperLight,
      reason: 'the colour plumbing still works when a caller supplies it',
    );
    expect(
      RCrmTheme.primaryFor(RCrmAccent.materialYou, Brightness.dark),
      wallpaperDark,
    );
    // onPrimary is measured, not assumed: the dark wallpaper colour is light.
    expect(
      RCrmTheme.onPrimaryFor(
        RCrmAccent.materialYou,
        Brightness.dark,
        wallpaperDark,
      ),
      const Color(0xFF101010),
    );
    RCrmColors.setSystemColors();
  });

  test(
    'Day and Night build different canvases; the accent deepens on cream',
    () {
      for (final accent in RCrmAccent.values) {
        // Custom's shades are derived, not fixed constants — see the dedicated
        // contrast test above.
        if (accent == RCrmAccent.custom) continue;
        final night = RCrmTheme.build(
          accent: accent,
          brightness: Brightness.dark,
        );
        final day = RCrmTheme.build(
          accent: accent,
          brightness: Brightness.light,
        );
        expect(night.scaffoldBackgroundColor, RCrmColors.darkPitch);
        expect(day.scaffoldBackgroundColor, RCrmColors.lightPitch);
        expect(night.colorScheme.primary, accent.dark);
        expect(
          day.colorScheme.primary,
          accent.light,
          reason: '${accent.label} must be readable on cream',
        );
      }
    },
  );

  test('applying the palette flips every ramp step and the ink', () {
    RCrmColors.apply(accent: RCrmAccent.footlight, brightness: Brightness.dark);
    expect(RCrmColors.primary, RCrmAccent.footlight.dark);
    expect(RCrmColors.pitch, RCrmColors.darkPitch);
    expect(RCrmColors.coal, RCrmColors.darkCoal);
    expect(RCrmColors.textPrimary, RCrmColors.darkWhite);

    RCrmColors.apply(
      accent: RCrmAccent.footlight,
      brightness: Brightness.light,
    );
    expect(RCrmColors.primary, RCrmAccent.footlight.light);
    expect(RCrmColors.pitch, RCrmColors.lightPitch);
    expect(RCrmColors.ash, RCrmColors.lightAsh);
    expect(RCrmColors.char, RCrmColors.lightChar);
    expect(RCrmColors.coal, RCrmColors.lightCoal);
    expect(RCrmColors.textPrimary, RCrmColors.lightInk);
    expect(RCrmColors.textSecondary, RCrmColors.lightInkSubtle);
  });

  test('every status token reads on its own canvas, in both appearances', () {
    // These are ICONS and small labels, so 3:1 is the floor (WCAG 1.4.11),
    // not the 4.5:1 body-text one. The numbers were 1.27:1 and 2.04:1 before
    // the Day ramp existed: the colours were the Night ones, hardcoded.
    for (final brightness in [Brightness.dark, Brightness.light]) {
      RCrmColors.apply(accent: RCrmAccent.marquee, brightness: brightness);
      for (final entry in {
        'ok': RCrmColors.ok,
        'warn': RCrmColors.warn,
        'bad': RCrmColors.bad,
      }.entries) {
        expect(
          _contrast(entry.value, RCrmColors.char),
          greaterThanOrEqualTo(3.0),
          reason: '${entry.key} on char must read in $brightness',
        );
      }
    }
  });

  test('the notice banner reads over the camera AND on the canvas', () {
    // It floats on the camera preview — arbitrary video pixels — and falls
    // back to the page canvas when the camera is not there. The file's own
    // literals were a cream chip with brown ink: 1.01:1 against the Day
    // canvas, i.e. the banner was simply invisible.
    //
    // The promise is the TEXT, not the chip's edge: the chip is opaque, so
    // the message never sits on video pixels. Its own separation is measured
    // against the two surfaces it can land on — the canvas and a card. (No
    // single colour separates from BOTH pure-white and pure-black video; that
    // is what the border is for, and why the chip is opaque in the first
    // place.)
    for (final brightness in [Brightness.dark, Brightness.light]) {
      RCrmColors.apply(accent: RCrmAccent.marquee, brightness: brightness);
      final surface = RCrmColors.noticeSurface;
      final ink = RCrmColors.noticeInk;

      expect(
        _contrast(ink, surface),
        greaterThanOrEqualTo(4.5),
        reason: 'the message must be body-text readable in $brightness',
      );
      expect(
        surface.a,
        1.0,
        reason: 'an opaque chip is what keeps the text off the video',
      );
      for (final canvas in <String, Color>{
        'the page canvas': RCrmColors.pitch,
        'a card': RCrmColors.char,
      }.entries) {
        expect(
          _contrast(surface, canvas.value),
          greaterThanOrEqualTo(1.4),
          reason: 'the chip must separate from ${canvas.key} in $brightness',
        );
      }
    }
  });

  testWidgets('the Appearance rows are one door each, and write through', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(1000, 1600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: c,
        child: MaterialApp(theme: RCrmTheme.dark, home: const SettingsScreen()),
      ),
    );
    await tester.pump();

    expect(find.text('Appearance'), findsOneWidget);
    for (final label in ['System', 'Day', 'Night']) {
      expect(find.text(label), findsOneWidget, reason: label);
    }
    // Colour is never the only carrier of state: every swatch is named.
    for (final a in RCrmAccent.values) {
      // No platform dynamic scheme in a widget test: Device is not offered.
      if (a == RCrmAccent.materialYou && !RCrmColors.hasSystemColor) continue;
      expect(find.text(a.label), findsOneWidget, reason: a.label);
    }

    final notifier = c.read(uiSettingsProvider.notifier);
    expect(c.read(uiSettingsProvider).appearanceMode, 'system');

    await tester.tap(find.text('Day'));
    await tester.pump();
    expect(c.read(uiSettingsProvider).appearanceMode, 'day');
    expect(await SettingsService().getAppearanceMode(), 'day');

    await tester.tap(find.text('Safelight'));
    await tester.pump();
    expect(c.read(uiSettingsProvider).appearanceAccent, 'safelight');
    expect(await SettingsService().getAppearanceAccent(), 'safelight');

    // A second door to the same setting would be a defect: switching the mode
    // must not silently change the accent, and vice versa.
    await tester.tap(find.text('Night'));
    await tester.pump();
    expect(c.read(uiSettingsProvider).appearanceMode, 'night');
    expect(c.read(uiSettingsProvider).appearanceAccent, 'safelight');
    expect(notifier.state.appearanceMode, 'night');
    expect(tester.takeException(), isNull);
  });
}
