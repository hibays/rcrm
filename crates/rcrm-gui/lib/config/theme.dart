// config/theme.dart
// RCrm GUI — "The Midnight Gallery" and its daylight extension (docs/DESIGN.md)
//
// Two appearances, one world. Night is the original dark room: five warm-
// tinted neutral steps from pitch to white, one rare Marquee Orange. Day keeps
// the same five-step tonal layering and the same accent family, inverted onto
// the app icon's cream (#F6F1E9) — never a generic white/blue SaaS surface.
// Depth still comes from tone, never shadows; the accent still means action.
//
// The runtime palette is a single mutable snapshot (RCrmColors), written once
// per frame from MaterialApp.builder via [RCrmTheme.applyToContext]. It is the
// same shape as the app's other process-wide gates (ThumbCache.enabled,
// PreviewPlayer.enabled): ThemeData is built as a PURE function, and the
// effective brightness is only known once a Theme exists. Two ThemeData objects
// (theme + darkTheme) are therefore built without touching global state; the
// builder applies exactly the one that Flutter actually selected.
//
// Media overlays — player chrome gradients, viewer scrims, badges painted ON
// TOP of video/photo pixels — deliberately do not follow the page appearance.
// They must stay legible over any frame, bright or dark. See docs/DESIGN.md.

import 'dart:io' show Platform;

import 'package:flutter/material.dart';

/// Five preset accents, all drawn from the theatre/darkroom world.
///
/// [dark] is the saturated brand colour used on the dark canvas (5.9–11.1:1
/// against pitch). [light] is its deepened counterpart for text and icons on
/// cream (4.8–7.6:1 against pitch, ≥4.7:1 on cards). [warm] is the lighter
/// variant reserved for the selected bottom-nav item on Night.
enum RCrmAccent {
  marquee(
    'marquee',
    'Marquee',
    Color(0xFFFF6B00),
    Color(0xFF9E3E00),
    Color(0xFFFF9900),
  ),
  safelight(
    'safelight',
    'Safelight',
    Color(0xFFFF4D4D),
    Color(0xFFB01F1F),
    Color(0xFFFF7070),
  ),
  projector(
    'projector',
    'Projector',
    Color(0xFFFFB800),
    Color(0xFF7A4F00),
    Color(0xFFFFC933),
  ),
  footlight(
    'footlight',
    'Footlight',
    Color(0xFFB57BFF),
    Color(0xFF5F30A8),
    Color(0xFFC99BFF),
  ),
  neon('neon', 'Neon', Color(0xFF00D9C0), Color(0xFF006A61), Color(0xFF33E8D6)),

  /// Android 12+ Material You. Its colours are NOT constants — they come from
  /// the wallpaper at runtime through `DynamicColorBuilder` and are stored in
  /// [RCrmColors.setSystemColors]. These three values are only the neutral
  /// fallback for a platform that reports no dynamic scheme (in which case the
  /// swatch is hidden altogether).
  materialYou(
    'material_you',
    'Device',
    Color(0xFF9E9E9E),
    Color(0xFF616161),
    Color(0xFFBDBDBD),
  );

  const RCrmAccent(this.key, this.label, this.dark, this.light, this.warm);

  /// Stable persisted value — never the display label.
  final String key;

  /// Shown next to the swatch: colour is never the only carrier of state.
  final String label;
  final Color dark;
  final Color light;
  final Color warm;

  Color on(Brightness brightness) =>
      brightness == Brightness.dark ? dark : light;

  /// Whitelist on the read side: an unknown or hand-edited value falls back to
  /// the original Marquee Orange rather than becoming a whole new appearance.
  static RCrmAccent fromKey(String? key) {
    for (final a in values) {
      if (a.key == key) return a;
    }
    return RCrmAccent.marquee;
  }
}

/// The three appearances. System follows the platform, Day and Night pin one.
enum RCrmAppearance { system, day, night }

/// The CURRENT palette. Getters (not `const`) so a Day/Night/accent switch can
/// be read by the ~70 existing `RCrmColors.*` call sites without rewriting
/// each one into a BuildContext lookup.
abstract final class RCrmColors {
  // ── Fixed brand constants (compile-time, safe in const expressions) ──
  static const marqueeOrange = Color(0xFFFF6B00);
  static const marqueeWarm = Color(0xFFFF9900);
  static const darkPitch = Color(0xFF0E0E0E);
  static const darkAsh = Color(0xFF1A1A1A);
  static const darkChar = Color(0xFF222222);
  static const darkCoal = Color(0xFF2A2A2A);
  static const darkDim = Color(0xFF3A3A3A);
  static const darkWhite = Color(0xFFFFFFFF);
  static const darkSilver = Color(0xFFAAAAAA);
  static const darkSilverFaint = Color(0xFF8A8A8A);
  static const lightPitch = Color(0xFFF6F1E9); // the app icon's cream
  static const lightAsh = Color(0xFFEDE7DC);
  static const lightChar = Color(0xFFE3DCCD);
  static const lightCoal = Color(0xFFD6CEBE);
  static const lightDim = Color(0xFFC4BBA8);
  static const lightInk = Color(0xFF1A1613);
  static const lightInkSubtle = Color(0xFF5C5348);
  static const lightInkFaint = Color(0xFF6B6154);

  // ── Mutable snapshot ────────────────────────────────────────
  static Color _primary = RCrmAccent.marquee.dark;
  static Color _primaryWarm = RCrmAccent.marquee.warm;
  static Color _onPrimary = const Color(0xFF101010);
  static Color _pitch = darkPitch;
  static Color _ash = darkAsh;
  static Color _char = darkChar;
  static Color _coal = darkCoal;
  static Color _dim = darkDim;
  static Color _textPrimary = darkWhite;
  static Color _textSecondary = darkSilver;
  static Color _textFaint = darkSilverFaint;
  static Color _textDim = const Color(0x33FFFFFF);
  static Color _hairline = const Color(0x14FFFFFF);

  // ── The media world: FIXED, never follows Day/Night ───────
  // Player chrome, viewer scrims, episode sheets and the up-next card sit on
  // top of unknown video/photo pixels. They must stay dark-on-white in BOTH
  // appearances, so they read these tokens instead of the page ones. Reading
  // `ash`/`primary`/`textDim` there was the bug: in Day those turn cream, a
  // deep orange and 20% black, which vanish over a dark frame.

  // The VIDEO PLAYER follows the appearance (it is a page, not a floating
  // badge): its scaffold, gradients, controls, panels and menus all use the
  // page tokens. Only the gradient START colour needs a token of its own,
  // because it has to be opaque enough for the text sitting on it.
  static Color _playerAccent = RCrmAccent.marquee.dark;

  // ── Player chrome: the ORIGINAL dark world, in BOTH appearances ──
  // The two gradients above and below the picture (and the menus, settings
  // panel and episode sheet that float on it) are an ink layer over unknown
  // video frames. They do NOT follow Day/Night: no cream bars, and no extra
  // stop / thickness / width added to make a light version readable. This is
  // exactly the dark treatment the player always had.
  // The player PAGE is separate — its scaffold, title and Related list do
  // follow the appearance and keep their semantic ink.

  /// The chosen accent's NIGHT variant, so theme-colour selection still applies
  /// inside the player but never turns into a deep Day tone on black.
  static Color get playerAccent => _playerAccent;

  /// Original two-stop scrims. Nothing added to their length or width.
  static Color get playerScrim => const Color(0x80000000);
  static Color get playerScrimStrong => const Color(0xB3000000);

  /// Fixed white ink, tracks, hairlines and surfaces over the picture.
  static Color get playerText => darkWhite;
  static Color get playerTextSecondary => darkSilver;
  static Color get playerTextFaint => darkSilverFaint;
  static Color get playerTrack => const Color(0x33FFFFFF);
  static Color get playerHairline => const Color(0x14FFFFFF);
  static Color get playerSurface => darkAsh;

  /// Text over a PHOTO — only the image viewer's top bar uses these. It floats
  /// on a black scrim above the picture (which is always the subject), so it
  /// stays white in both appearances. The video player's floating chrome uses
  /// the `player*` tokens above; only its page surfaces follow the appearance.
  static Color get mediaText => darkWhite;
  static Color get mediaTextSecondary => darkSilver;

  /// Page hairline: 8% of the current ink, so it stays a hairline in Day
  /// instead of becoming a 20% rule.
  static Color get hairline => _hairline;

  // ── Status colours (doctor panel) ─────────────────────────
  // Day needs the deep variants: Material's green 500 / orange / red 500 all
  // land at 1.7–3.0:1 on cream.
  static Color _ok = const Color(0xFF4CAF50);
  static Color _warn = const Color(0xFFFFB74D);
  static Color _bad = const Color(0xFFEF5350);
  static Color get ok => _ok;
  static Color get warn => _warn;
  static Color get bad => _bad;

  // ── Android 12+ Material You ──────────────────────────────
  static Color? _systemLight;
  static Color? _systemDark;

  /// True only when the platform actually supplied BOTH dynamic schemes. The
  /// Settings swatch is hidden when false: a control that cannot act is not
  /// offered at all (docs/DESIGN.md), and desktop/iOS/old Android have no
  /// wallpaper colour to give.
  /// Android only, on purpose: `dynamic_color` also returns a desktop accent
  /// (macOS 10.14+, Windows Vista+, GTK), and offering that swatch on a desktop
  /// would let the system's blue replace the brand accent. The feature was
  /// asked for on Android; elsewhere the preset set is the whole story.
  static bool get hasSystemColor =>
      Platform.isAndroid && _systemLight != null && _systemDark != null;
  static Color? get systemLight => _systemLight;
  static Color? get systemDark => _systemDark;

  /// Called once per build from `DynamicColorBuilder` in app.dart.
  static void setSystemColors({Color? light, Color? dark}) {
    _systemLight = light;
    _systemDark = dark;
  }

  /// Accent: action, focus, progress, selection. On Day it is the deepened
  /// variant so it stays readable on cream; [onPrimary] flips accordingly.
  static Color get primary => _primary;

  /// Selected bottom-nav item. Warm/lighter on Night, deepened on Day.
  static Color get primaryWarm => _primaryWarm;

  /// Text/icon drawn ON a primary fill.
  static Color get onPrimary => _onPrimary;

  /// Canvas, surface, card, placeholder, divider — the five tonal steps.
  static Color get pitch => _pitch;
  static Color get ash => _ash;
  static Color get char => _char;
  static Color get coal => _coal;
  static Color get dim => _dim;

  /// Primary / secondary / faint text. "Silver is silver, not ash": Day keeps
  /// the same ≥6:1 contrast rather than drifting to a light gray.
  static Color get textPrimary => _textPrimary;
  static Color get textSecondary => _textSecondary;
  static Color get textFaint => _textFaint;

  /// 20% ink/white — inactive tracks, disabled elements.
  static Color get textDim => _textDim;

  /// The single write point. Called from [RCrmTheme.applyToContext].
  static void apply({
    required RCrmAccent accent,
    required Brightness brightness,
  }) {
    final dark = brightness == Brightness.dark;
    _primary = RCrmTheme.primaryFor(accent, brightness);
    _primaryWarm = accent == RCrmAccent.materialYou
        ? _primary
        : (dark ? accent.warm : accent.light);
    _onPrimary = RCrmTheme.onPrimaryFor(accent, brightness, _primary);
    _pitch = dark ? darkPitch : lightPitch;
    _ash = dark ? darkAsh : lightAsh;
    _char = dark ? darkChar : lightChar;
    _coal = dark ? darkCoal : lightCoal;
    _dim = dark ? darkDim : lightDim;
    _textPrimary = dark ? darkWhite : lightInk;
    _textSecondary = dark ? darkSilver : lightInkSubtle;
    _textFaint = dark ? darkSilverFaint : lightInkFaint;
    _textDim = dark ? const Color(0x33FFFFFF) : const Color(0x33000000);
    _hairline = dark ? const Color(0x14FFFFFF) : const Color(0x14000000);
    // Player chrome is appearance-independent, but the accent the user picked
    // still applies — always its Night (bright) variant, legible on black.
    _playerAccent = accent == RCrmAccent.materialYou
        ? (_systemDark ?? RCrmAccent.marquee.dark)
        : accent.dark;
    _ok = dark ? const Color(0xFF4CAF50) : const Color(0xFF1B5E20);
    _warn = dark ? const Color(0xFFFFB74D) : const Color(0xFF8A5A00);
    _bad = dark ? const Color(0xFFEF5350) : const Color(0xFFC62828);
  }
}

/// Corner radii — sm for chips/badges, md for cards/containers.
abstract final class RCrmRadii {
  static const sm = 4.0;
  static const md = 8.0;
}

/// Spacing scale — 4/8/16/24. Generous in grids, tight in chrome.
abstract final class RCrmSpacing {
  static const xs = 4.0;
  static const sm = 8.0;
  static const md = 16.0;
  static const lg = 24.0;
}

/// Theme builder — the app's single source of ThemeData.
abstract final class RCrmTheme {
  /// The original Night world. Kept as the test fixture for the whole suite.
  static ThemeData get dark => build(
    accent: RCrmAccent.marquee,
    brightness: Brightness.dark,
  );

  /// The effective accent: a preset's own colour, or the OS-supplied Material
  /// You primary when that swatch is active. Shared by ThemeData and the
  /// runtime snapshot so they can never disagree.
  static Color primaryFor(RCrmAccent accent, Brightness brightness) {
    if (accent == RCrmAccent.materialYou) {
      final c = brightness == Brightness.dark
          ? RCrmColors.systemDark
          : RCrmColors.systemLight;
      if (c != null) return c;
    }
    return accent.on(brightness);
  }

  /// Text ON a primary fill. A wallpaper colour has no known lightness, so it
  /// is measured instead of assumed; presets keep their fixed pair.
  static Color onPrimaryFor(
    RCrmAccent accent,
    Brightness brightness,
    Color primary,
  ) {
    if (accent == RCrmAccent.materialYou) {
      return primary.computeLuminance() > 0.5
          ? const Color(0xFF101010)
          : const Color(0xFFFFFFFF);
    }
    return brightness == Brightness.dark
        ? const Color(0xFF101010)
        : const Color(0xFFFFFFFF);
  }

  /// PURE: builds a ThemeData without touching the runtime palette. Both
  /// `theme` and `darkTheme` can therefore be built in the same frame.
  static ThemeData build({
    required RCrmAccent accent,
    required Brightness brightness,
  }) {
    final dark = brightness == Brightness.dark;
    final primary = primaryFor(accent, brightness);
    final pitch = dark ? RCrmColors.darkPitch : RCrmColors.lightPitch;
    final ash = dark ? RCrmColors.darkAsh : RCrmColors.lightAsh;
    final char = dark ? RCrmColors.darkChar : RCrmColors.lightChar;
    final dim = dark ? RCrmColors.darkDim : RCrmColors.lightDim;
    final ink = dark ? RCrmColors.darkWhite : RCrmColors.lightInk;
    final subtle = dark ? RCrmColors.darkSilver : RCrmColors.lightInkSubtle;
    final faint = dark ? RCrmColors.darkSilverFaint : RCrmColors.lightInkFaint;
    final onPrimary = onPrimaryFor(accent, brightness, primary);

    final base = dark ? ThemeData.dark() : ThemeData.light();
    final theme = base.copyWith(
      scaffoldBackgroundColor: pitch,
      canvasColor: pitch,
      cardColor: char,
      dialogTheme: DialogThemeData(backgroundColor: ash),
      dividerColor: dim,
      hintColor: subtle,
      disabledColor: dark ? const Color(0x33FFFFFF) : const Color(0x33000000),
      colorScheme: (dark
              ? ColorScheme.dark(
                  primary: primary,
                  surface: ash,
                  onSurface: ink,
                )
              : ColorScheme.light(
                  primary: primary,
                  surface: ash,
                  onSurface: ink,
                ))
          .copyWith(
        primary: primary,
        onPrimary: onPrimary,
        surface: ash,
        onSurface: ink,
        onSurfaceVariant: subtle,
        // A border is a control boundary: it owes 3:1, which `dim` (1.35–1.55)
        // never had. `faint` is 5.0 in Night and 4.9 in Day.
        outline: faint,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: ash,
        foregroundColor: ink,
        elevation: 0,
      ),
      bottomNavigationBarTheme: BottomNavigationBarThemeData(
        backgroundColor: ash,
        selectedItemColor: accent == RCrmAccent.materialYou
            ? primary
            : (dark ? accent.warm : accent.light),
        unselectedItemColor: subtle,
        type: BottomNavigationBarType.fixed,
      ),
      iconTheme: IconThemeData(color: ink),
      primaryIconTheme: IconThemeData(color: ink),
      listTileTheme: ListTileThemeData(
        textColor: ink,
        iconColor: subtle,
        tileColor: Colors.transparent,
      ),
      segmentedButtonTheme: SegmentedButtonThemeData(
        style: ButtonStyle(
          backgroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected) ? primary : null,
          ),
          foregroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected)
                ? onPrimary
                : subtle,
          ),
        ),
      ),
      sliderTheme: SliderThemeData(
        activeTrackColor: primary,
        thumbColor: primary,
        inactiveTrackColor: dark
            ? const Color(0x33FFFFFF)
            : const Color(0x33000000),
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(color: primary),
      textTheme: base.textTheme.apply(bodyColor: ink, displayColor: ink),
    );

    if (!_isDesktop) return theme;
    return theme.copyWith(
      textTheme: theme.textTheme.apply(
        fontFamilyFallback: const ['Microsoft YaHei', 'PingFang SC', 'SimHei'],
      ),
    );
  }

  /// Called once from MaterialApp.builder, AFTER Flutter has resolved which of
  /// the two ThemeData objects actually applies. This is the palette's only
  /// write point, so `RCrmColors.*` always matches `Theme.of(context)`.
  static void applyToContext(BuildContext context, RCrmAccent accent) =>
      RCrmColors.apply(
        accent: accent,
        brightness: Theme.of(context).brightness,
      );

  static final bool _isDesktop =
      Platform.isWindows || Platform.isMacOS || Platform.isLinux;
}
