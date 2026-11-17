// test/keyword_filter_bar_test.dart
// The bar's chips own their colour in EVERY state.
//
// FilterChip ships an M3 default `color` (a WidgetStateProperty that resolves
// to `secondaryContainer`) which outranks `selectedColor` while the selection
// and enable animations still overlap. In this palette that is a teal flash
// between the click and the orange — measured on a real frame 40ms after the
// tap. These tests pin the chip's own colour for every ink state, so no default
// has anything left to paint.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/utils/keywords.dart';
import 'package:rcrm_gui/widgets/keyword_chip.dart';
import 'package:rcrm_gui/widgets/keyword_filter_bar.dart';

Future<void> _pumpBar(
  WidgetTester tester, {
  required Set<String> selected,
}) async {
  await tester.binding.setSurfaceSize(const Size(700, 120));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      home: Scaffold(
        body: KeywordFilterBar(
          tags: const [
            KeywordTag('amateur', 'Amateur'),
            KeywordTag('mayvid', 'Mayvid'),
          ],
          selected: selected,
          onToggle: (_) {},
          onClear: () {},
        ),
      ),
    ),
  );
  await tester.pump();
}

/// Every state a pointer can put a chip in, including the combinations that
/// used to fall through to the M3 default.
const Map<String, Set<WidgetState>> _inkStates = {
  'rest': <WidgetState>{},
  'hovered': {WidgetState.hovered},
  'pressed': {WidgetState.pressed},
  'focused': {WidgetState.focused},
  'selected': {WidgetState.selected},
  'selected+pressed': {WidgetState.selected, WidgetState.pressed},
  'selected+hovered': {WidgetState.selected, WidgetState.hovered},
};

void main() {
  testWidgets('a chip paints its own colours in every ink state', (
    tester,
  ) async {
    await _pumpBar(tester, selected: const {});

    // Off: Char. On: Marquee Orange. Nothing else, in ANY state — a null
    // `color` would let M3 answer with `secondaryContainer` (teal).
    for (final label in ['All tags', 'Amateur']) {
      final chip = tester.widget<FilterChip>(
        find.widgetWithText(FilterChip, label),
      );
      expect(
        chip.color,
        isNotNull,
        reason: '$label must not fall through to the M3 default fill',
      );
      for (final entry in _inkStates.entries) {
        final fill = chip.color!.resolve(entry.value);
        expect(
          fill,
          anyOf(RCrmColors.char, RCrmColors.primary),
          reason: '$label in ${entry.key} resolved to $fill',
        );
        if (entry.value.contains(WidgetState.selected)) {
          expect(fill, RCrmColors.primary, reason: '$label in ${entry.key}');
        } else {
          expect(fill, RCrmColors.char, reason: '$label in ${entry.key}');
        }
      }
    }
  });

  testWidgets('a selected chip is orange and the rest stay Char', (
    tester,
  ) async {
    await _pumpBar(tester, selected: const {'amateur'});

    Color? fillOf(String label) {
      final chip = tester.widget<FilterChip>(
        find.widgetWithText(FilterChip, label),
      );
      return chip.color!.resolve(
        chip.selected ? {WidgetState.selected} : <WidgetState>{},
      );
    }

    expect(fillOf('Amateur'), RCrmColors.primary);
    expect(fillOf('Mayvid'), RCrmColors.char);
    expect(fillOf('All tags'), RCrmColors.char);
  });

  testWidgets('the selected-tag chip in search pins its fill too', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(400, 120));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      MaterialApp(
        theme: RCrmTheme.dark,
        home: Scaffold(
          body: SelectedKeywordChip(
            tag: const KeywordTag('amateur', 'Amateur'),
            onRemove: () {},
          ),
        ),
      ),
    );
    await tester.pump();

    final chip = tester.widget<FilterChip>(find.byType(FilterChip));
    expect(chip.color, isNotNull);
    // A selected chip's live states ALWAYS carry `selected`; the pointer states
    // below are added on top of it.
    for (final entry in _inkStates.entries) {
      final states = {...entry.value, WidgetState.selected};
      expect(
        chip.color!.resolve(states),
        RCrmColors.primary,
        reason: 'a selected chip is orange in ${entry.key}, never teal',
      );
    }
  });

  test('the palette really does have a teal secondaryContainer to leak', () {
    // Guards the premise of the three tests above: if the theme ever pins a
    // secondaryContainer equal to a colour we use, the assertions would pass
    // for the wrong reason and stop protecting anything.
    final scheme = RCrmTheme.dark.colorScheme;
    expect(scheme.secondaryContainer, isNot(RCrmColors.primary));
    expect(scheme.secondaryContainer, isNot(RCrmColors.char));
  });
}
