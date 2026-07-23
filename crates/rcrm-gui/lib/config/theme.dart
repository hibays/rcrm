// config/theme.dart
// RCrm GUI — dark theme configuration
import 'package:flutter/material.dart';

class AppTheme {
  static const _primaryColor = Color(0xFFFF6B00); // Orange accent
  static const _backgroundColor = Color(0xFF0E0E0E); // Near-black
  static const _surfaceColor = Color(0xFF1A1A1A);
  static const _cardColor = Color(0xFF222222);
  static const _textPrimary = Color(0xFFFFFFFF);
  static const _textSecondary = Color(0xFFAAAAAA);

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: _backgroundColor,
      primaryColor: _primaryColor,
      colorScheme: const ColorScheme.dark(
        primary: _primaryColor,
        secondary: _primaryColor,
        surface: _surfaceColor,
        onPrimary: Colors.white,
        onSecondary: Colors.white,
        onSurface: _textPrimary,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: _surfaceColor,
        foregroundColor: _textPrimary,
        elevation: 0,
        centerTitle: false,
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: _surfaceColor,
        selectedItemColor: _primaryColor,
        unselectedItemColor: _textSecondary,
        type: BottomNavigationBarType.fixed,
      ),
      cardTheme: CardThemeData(
        color: _cardColor,
        elevation: 2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
      iconTheme: const IconThemeData(color: _textPrimary),
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          color: _textPrimary,
          fontWeight: FontWeight.bold,
        ),
        headlineMedium: TextStyle(
          color: _textPrimary,
          fontWeight: FontWeight.w600,
        ),
        titleLarge: TextStyle(color: _textPrimary, fontWeight: FontWeight.w600),
        titleMedium: TextStyle(color: _textPrimary),
        bodyLarge: TextStyle(color: _textPrimary),
        bodyMedium: TextStyle(color: _textSecondary),
        labelLarge: TextStyle(color: _textPrimary, fontWeight: FontWeight.w600),
      ),
      sliderTheme: SliderThemeData(
        activeTrackColor: _primaryColor,
        thumbColor: _primaryColor,
        inactiveTrackColor: _textSecondary.withValues(alpha: 0.3),
      ),
    );
  }
}
