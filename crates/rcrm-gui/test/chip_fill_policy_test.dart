// test/chip_fill_policy_test.dart
//
// ONE property, enforced twice: a SELECTABLE chip in this app always pins its
// own fill (`color`) for every ink state.
//
// Why: `FilterChip`'s M3 default `color` is a WidgetStateProperty that resolves
// to `secondaryContainer` — teal in this palette — and it outranks
// `selectedColor` for the frames where the selection and enable animations
// still overlap. That produced a visible teal frame between the tap and the
// orange at three call sites in one evening (the toolbar's Tags chip, the tag
// filter bar, and search's selected-tag chip).
//
// The widget those last two now share (`widgets/filter_tag_chip.dart`) pins the
// whole look, so a new chip cannot forget a property by copying it. These tests
// are what stops the next call site from hand-rolling a fourth.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/utils/keywords.dart';
import 'package:rcrm_gui/widgets/keyword_chip.dart';
import 'package:rcrm_gui/widgets/keyword_filter_bar.dart';
import 'package:rcrm_gui/widgets/media_toolbar.dart';

/// A selectable chip constructor call found in `lib/`, with the text of its own
/// argument list (nested widgets excluded by the depth walk below).
class _ChipCall {
  final String file;
  final int line;
  final String args;

  const _ChipCall(this.file, this.line, this.args);

  @override
  String toString() => '$file:$line';
}

final _selectableChipCtor = RegExp(r'\b(FilterChip|ChoiceChip|InputChip)\s*\(');

int _matchingParen(String source, int openIndex) {
  var depth = 0;
  for (var i = openIndex; i < source.length; i++) {
    final unit = source.codeUnitAt(i);
    if (unit == 0x28) {
      depth++;
    } else if (unit == 0x29) {
      depth--;
      if (depth == 0) return i;
    }
  }
  return -1;
}

int _lineOf(String source, int index) =>
    '\n'.allMatches(source.substring(0, index)).length + 1;

/// True when [name] is passed to the call ITSELF, not to a widget nested inside
/// its arguments (a `ButtonStyle(color: …)` must not count).
bool _hasOwnArgument(String args, String name) {
  var depth = 0;
  for (var i = 0; i < args.length; i++) {
    final unit = args.codeUnitAt(i);
    switch (unit) {
      case 0x28 || 0x5B || 0x7B: // ( [ {
        depth++;
      case 0x29 || 0x5D || 0x7D: // ) ] }
        depth--;
      default:
        if (depth == 0 && args.startsWith('$name:', i)) return true;
    }
  }
  return false;
}

List<_ChipCall> _scanSelectableChips() {
  final lib = Directory('lib');
  expect(
    lib.existsSync(),
    isTrue,
    reason: 'the scan must run from the package root',
  );
  final calls = <_ChipCall>[];
  for (final entity in lib.listSync(recursive: true)) {
    if (entity is! File || !entity.path.endsWith('.dart')) continue;
    final source = entity.readAsStringSync();
    for (final match in _selectableChipCtor.allMatches(source)) {
      final open = match.end - 1;
      final close = _matchingParen(source, open);
      if (close < 0) continue;
      calls.add(
        _ChipCall(
          entity.path.replaceAll(Platform.pathSeparator, '/'),
          _lineOf(source, match.start),
          source.substring(open + 1, close),
        ),
      );
    }
  }
  return calls;
}

Future<void> _pump(WidgetTester tester, Widget child) async {
  await tester.binding.setSurfaceSize(const Size(700, 200));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      home: Scaffold(body: Center(child: child)),
    ),
  );
  await tester.pump();
}

void main() {
  test('the scanner finds the app\'s selectable chip call sites', () {
    final calls = _scanSelectableChips();
    // The two real ones: the shared widget (both tag surfaces go through it)
    // and the toolbar's Tags chip, which stays a raw FilterChip so it can look
    // like the Chips beside it. A regex that quietly stops matching would make
    // the assertion below pass for the wrong reason.
    expect(
      calls.map((c) => c.file).toSet(),
      containsAll(<String>[
        'lib/widgets/filter_tag_chip.dart',
        'lib/widgets/media_toolbar.dart',
      ]),
    );
  });

  test('the argument walk counts only the chip\'s own arguments', () {
    // Proves the detector can DISCRIMINATE, not just find the string somewhere:
    // a `color:` that belongs to a nested widget is not a pin on the chip.
    expect(_hasOwnArgument('selected: true, color: X', 'color'), isTrue);
    expect(
      _hasOwnArgument(
        'label: Text("x"), style: ButtonStyle(color: X)',
        'color',
      ),
      isFalse,
      reason: 'that colour belongs to the ButtonStyle, not to the chip',
    );
    expect(
      _hasOwnArgument('selected: true, side: BorderSide.none', 'color'),
      isFalse,
    );
  });

  test('every selectable chip pins its own fill', () {
    final offenders = [
      for (final call in _scanSelectableChips())
        if (!_hasOwnArgument(call.args, 'color')) '$call',
    ];
    expect(
      offenders,
      isEmpty,
      reason:
          'FilterChip\'s default `color` resolves to M3 `secondaryContainer` '
          '(teal in this palette) while the selection and enable animations '
          'overlap. Either use FilterTagChip, or pin `color` at this call site.',
    );
  });

  testWidgets('the tag bar\'s chips resolve their own fill', (tester) async {
    await _pump(
      tester,
      KeywordFilterBar(
        tags: const [KeywordTag('amateur', 'Amateur')],
        selected: const {'amateur'},
        onToggle: (_) {},
        onClear: () {},
      ),
    );
    final chips = tester.widgetList<FilterChip>(find.byType(FilterChip));
    expect(chips, isNotEmpty);
    for (final chip in chips) {
      expect(chip.color, isNotNull);
    }
  });

  testWidgets('the toolbar\'s Tags chip resolves its own fill', (tester) async {
    await _pump(
      tester,
      MediaToolbar(
        sortOptions: const ['name'],
        currentSort: 'name',
        isAscending: true,
        onSortChanged: (_) {},
        onSortDirectionChanged: () {},
        tagBarVisible: false,
        onToggleTagBar: () {},
      ),
    );
    final chips = tester
        .widgetList<FilterChip>(find.byType(FilterChip))
        .toList();
    expect(chips, hasLength(1));
    expect(chips.single.color, isNotNull);
  });

  testWidgets('search\'s selected-tag chip resolves its own fill', (
    tester,
  ) async {
    await _pump(
      tester,
      SelectedKeywordChip(
        tag: const KeywordTag('amateur', 'Amateur'),
        onRemove: () {},
      ),
    );
    final chip = tester.widget<FilterChip>(find.byType(FilterChip));
    expect(chip.color, isNotNull);
    expect(chip.color!.resolve({WidgetState.selected}), RCrmColors.primary);
  });
}
