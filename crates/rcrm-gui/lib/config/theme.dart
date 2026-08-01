// config/theme.dart
// RCrm GUI — "The Midnight Gallery" design system (docs/DESIGN.md)
//
// A dark room where media hangs on the wall, lit by a single warm orange glow.
// Depth comes from tonal layering (pitch → ash → char → coal), never shadows.
// Surfaces are flat at rest; Marquee Orange appears only where something is
// happening — play, progress, selection, focus. The accent is rare (≤10% of
// any screen) because its rarity is the signal.
//
// Design tokens live here as the single source of truth. Screens should read
// colors/radii from this file (or Theme.of(context)) instead of hardcoding
// hex values.

import 'dart:io' show Platform;

import 'package:flutter/material.dart';

/// The Marquee Palette — one accent, five neutral steps from pitch to white.
///
/// Neutrals carry a trace of orange hue so the warm ramp reads as one family
/// (oklch hue 60 throughout), not a warm-on-gray accident.
abstract final class RCrmColors {
  // ── Accent (the Rarity Rule: ≤10% of any screen) ──────────
  /// Marquee Orange — play buttons, progress, slider thumbs/tracks, selected
  /// segment fills, loading spinners. Nothing else.
  static const primary = Color(0xFFFF6B00); // oklch(0.62 0.22 40)

  /// Warm Glow — exclusively for the selected bottom-nav item.
  static const primaryWarm = Color(0xFFFF9900); // oklch(0.72 0.18 60)

  // ── Neutral ramp (warm-tinted black) ──────────────────────
  /// Pitch — the canvas. Scaffold background.
  static const pitch = Color(0xFF0E0E0E); // oklch(0.035 0.005 60)

  /// Ash — surface layer. App bars, bottom nav, section backgrounds.
  static const ash = Color(0xFF1A1A1A); // oklch(0.13 0.005 60)

  /// Char — cards and containers. The main content surface.
  static const char = Color(0xFF222222); // oklch(0.18 0.005 60)

  /// Coal — image placeholders, shimmer base, empty-state fills.
  static const coal = Color(0xFF2A2A2A); // oklch(0.22 0.005 60)

  /// Dim highlight — shimmer sweep, subtle dividers.
  static const dim = Color(0xFF3A3A3A); // oklch(0.28 0.005 60)

  // ── Text ──────────────────────────────────────────────────
  /// Primary text, headlines, default icon color.
  static const white = Color(0xFFFFFFFF);

  /// Secondary text — 8:1 contrast on pitch. Silver is silver, not ash.
  static const silver = Color(0xFFAAAAAA); // oklch(0.72 0.008 60)

  /// 20% white — inactive slider track, disabled elements.
  static const silverDim = Color(0x33FFFFFF);
}

/// Corner radii — sm for chips/badges, md for cards/containers. Cards top out
/// at 8px; the system never over-rounds.
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
///
/// Dark-only by design ("The Midnight Gallery" lives in dim rooms; a light
/// theme would be a different product). Desktop builds append CJK font
/// fallbacks so Chinese file names render cleanly.
abstract final class RCrmTheme {
  static ThemeData get dark => _buildDark();

  static ThemeData _buildDark() {
    final isDesktop =
        Platform.isWindows || Platform.isMacOS || Platform.isLinux;

    // Visual parity with the original inline _buildTheme() — token names,
    // same values. No extra theme overrides (textTheme, cards, sliders,
    // dialogs stay at ThemeData.dark() defaults).
    final base = ThemeData.dark().copyWith(
      scaffoldBackgroundColor: RCrmColors.pitch,
      colorScheme: const ColorScheme.dark(primary: RCrmColors.primary),
      appBarTheme: const AppBarTheme(
        backgroundColor: RCrmColors.ash,
        elevation: 0,
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: RCrmColors.ash,
        selectedItemColor: RCrmColors.primaryWarm,
        unselectedItemColor: Colors.white54,
        type: BottomNavigationBarType.fixed,
      ),
      segmentedButtonTheme: SegmentedButtonThemeData(
        style: ButtonStyle(
          backgroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected)
                ? RCrmColors.primary
                : null,
          ),
          foregroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected)
                ? Colors.black
                : Colors.white70,
          ),
        ),
      ),
    );

    if (!isDesktop) return base;
    return base.copyWith(
      textTheme: base.textTheme.apply(
        fontFamilyFallback: const ['Microsoft YaHei', 'PingFang SC', 'SimHei'],
      ),
    );
  }
}
