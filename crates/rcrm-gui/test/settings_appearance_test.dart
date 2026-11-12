// test/settings_appearance_test.dart
// Appearance: System / Day / Night and the five preset accents.
//
// What is pinned here: both values round-trip through SharedPreferences with a
// whitelist on the read side; Day and Night really build different canvases and
// the accent deepens on cream; the runtime RCrmColors snapshot flips every ramp
// step; and the Settings row writes through on the same frame, with no restart.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  tearDown(() {
    // The palette is a process-wide snapshot; leave it as a fresh Night app
    // would find it so other tests in this file cannot inherit a Day ramp.
    RCrmColors.setSystemColors();
    RCrmColors.apply(
      accent: RCrmAccent.marquee,
      brightness: Brightness.dark,
    );
  });

  test('appearance mode round-trips, default SYSTEM, unknown falls back', () async {
    final s = SettingsService();
    expect(await s.getAppearanceMode(), 'system');

    for (final mode in ['day', 'night', 'system']) {
      await s.setAppearanceMode(mode);
      expect(await s.getAppearanceMode(), mode);
    }
    await s.setAppearanceMode('garbage');
    expect(await s.getAppearanceMode(), 'system',
        reason: 'a preference file this build did not write cannot invent a mode');
  });

  test('accent round-trips, default Marquee, unknown resolves at the consumer',
      () async {
    final s = SettingsService();
    expect(await s.getAppearanceAccent(), 'marquee');

    await s.setAppearanceAccent('neon');
    expect(await s.getAppearanceAccent(), 'neon');
    expect(RCrmAccent.fromKey('neon'), RCrmAccent.neon);
    expect(RCrmAccent.fromKey('garbage'), RCrmAccent.marquee);
    expect(RCrmAccent.fromKey(null), RCrmAccent.marquee);
  });

  test('six presets, distinct stable keys (incl. Material You)', () {
    expect(RCrmAccent.values, hasLength(6));
    expect(RCrmAccent.values.map((a) => a.key).toSet(), hasLength(6));
    expect(RCrmAccent.values.map((a) => a.dark).toSet(), hasLength(6));
    expect(RCrmAccent.values.map((a) => a.light).toSet(), hasLength(6));
  });

  test('Material You uses the OS colour, and hides itself when there is none',
      () {
    const wallpaperLight = Color(0xFF3F51B5);
    const wallpaperDark = Color(0xFFB0BEC5);
    expect(RCrmColors.hasSystemColor, isFalse);
    expect(
      RCrmTheme.primaryFor(RCrmAccent.materialYou, Brightness.light),
      RCrmAccent.materialYou.light,
      reason: 'no OS scheme -> neutral fallback, and the swatch is hidden',
    );

    RCrmColors.setSystemColors(
      light: wallpaperLight,
      dark: wallpaperDark,
    );
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

  test('Day and Night build different canvases; the accent deepens on cream', () {
    for (final accent in RCrmAccent.values) {
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
      expect(day.colorScheme.primary, accent.light,
          reason: '${accent.label} must be readable on cream');
    }
  });

  test('applying the palette flips every ramp step and the ink', () {
    RCrmColors.apply(accent: RCrmAccent.footlight, brightness: Brightness.dark);
    expect(RCrmColors.primary, RCrmAccent.footlight.dark);
    expect(RCrmColors.pitch, RCrmColors.darkPitch);
    expect(RCrmColors.coal, RCrmColors.darkCoal);
    expect(RCrmColors.textPrimary, RCrmColors.darkWhite);

    RCrmColors.apply(accent: RCrmAccent.footlight, brightness: Brightness.light);
    expect(RCrmColors.primary, RCrmAccent.footlight.light);
    expect(RCrmColors.pitch, RCrmColors.lightPitch);
    expect(RCrmColors.ash, RCrmColors.lightAsh);
    expect(RCrmColors.char, RCrmColors.lightChar);
    expect(RCrmColors.coal, RCrmColors.lightCoal);
    expect(RCrmColors.textPrimary, RCrmColors.lightInk);
    expect(RCrmColors.textSecondary, RCrmColors.lightInkSubtle);
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
