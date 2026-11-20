// test/media_toolbar_overflow_test.dart
//
// The narrow toolbar regression, pinned at the widths a phone actually uses:
// dropping a control may not mean losing its function, and the row may not end
// as a cluster of chips with a bare `#` and an empty right edge. The overflow
// button is the single right-edge answer; every dropped control is a row in it.

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/widgets/media_toolbar.dart';

MediaToolbar _bar(
  List<String> calls, {
  String sort = 'date',
  List<String> extensions = const ['mp4', 'mkv'],
}) => MediaToolbar(
  sortOptions: const ['name', 'date', 'size', 'duration'],
  currentSort: sort,
  isAscending: true,
  onSortChanged: (s) => calls.add('sort:$s'),
  onSortDirectionChanged: () => calls.add('direction'),
  extensions: extensions,
  currentFilter: 'mp4',
  onFilterChanged: (f) => calls.add('filter:$f'),
  currentColumns: 3,
  onColumnsChanged: (c) => calls.add('columns:$c'),
  minColumns: 2,
  maxColumns: 6,
  isGrid: true,
  onLayoutToggle: () => calls.add('layout'),
  currentGrouping: 'folder',
  onGroupingChanged: (g) => calls.add('group:$g'),
  tagBarVisible: false,
  onToggleTagBar: () => calls.add('tags'),
);

/// The toolbar fills its width (as it does in the app); the surface is tall so
/// a long overflow menu has room to open in the test.
Future<void> _pump(
  WidgetTester tester,
  Widget child,
  double width, {
  double textScale = 1,
  double height = 800,
}) async {
  await tester.binding.setSurfaceSize(Size(width, height));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      navigatorObservers: [FlutterSmartDialog.observer],
      builder: (context, appChild) => FlutterSmartDialog.init()(
        context,
        MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.linear(textScale)),
          child: appChild!,
        ),
      ),
      home: Scaffold(
        body: SizedBox(width: width, child: child),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  // The app configures `inside` in `app.dart`; without it a right-anchored
  // menu centres on the button's edge and hangs off a phone-width screen.
  late SmartConfigAttach previous;
  setUp(() {
    previous = SmartDialog.config.attach;
    SmartDialog.config.attach = SmartConfigAttach(
      attachAlignmentType: SmartAttachAlignmentType.inside,
    );
  });
  tearDown(() => SmartDialog.config.attach = previous);

  testWidgets('a wide bar shows controls inline and no overflow button', (
    tester,
  ) async {
    final calls = <String>[];
    await _pump(tester, _bar(calls), 1000);
    expect(find.byTooltip('More options'), findsNothing);
    expect(find.byTooltip('Organize'), findsOneWidget);
  });

  testWidgets('a narrow bar keeps a right-edge control and no bare #', (
    tester,
  ) async {
    for (final width in [414.0, 375.0, 320.0]) {
      final calls = <String>[];
      await _pump(tester, _bar(calls), width);

      final overflow = find.byTooltip('More options');
      expect(overflow, findsOneWidget, reason: 'width $width');
      final rect = tester.getRect(overflow);
      expect(
        rect.right,
        greaterThan(width - 24),
        reason: 'the overflow button must sit at the right edge, width $width',
      );

      // The lone `#` chip is gone; the tag toggle lives in the menu.
      expect(
        find.byType(FilterChip),
        findsNothing,
        reason: 'no compact bare-hash chip at width $width',
      );
    }
  });

  testWidgets('every dropped control is reachable from the overflow', (
    tester,
  ) async {
    final calls = <String>[];
    await _pump(tester, _bar(calls), 320);
    await tester.tap(find.byTooltip('More options'));
    await tester.pumpAndSettle();

    // At 320 everything optional is in the menu: filter, tag, sort direction,
    // organize, layout, and the whole column range.
    for (final label in [
      'All formats',
      'MP4',
      'MKV',
      'Show tag filters',
      'Sort descending',
      'Ungrouped',
      'By folder',
      'By format',
      'List view',
      '2 columns',
      '3 columns',
      '4 columns',
      '5 columns',
      '6 columns',
    ]) {
      expect(find.text(label), findsOneWidget, reason: 'missing $label');
    }
  });

  testWidgets('menu rows write through the same callbacks as inline controls', (
    tester,
  ) async {
    // A fresh bar per choice: the anchored dialog's mask lingers for a beat
    // after a row delivers its value, so reopening it in one test is flaky.
    // Each case proves one row reaches the same callback the inline control
    // would have called.
    for (final (label, expected) in [
      ('MKV', 'filter:mkv'),
      ('Show tag filters', 'tags'),
      ('Sort descending', 'direction'),
      ('By format', 'group:format'),
      ('List view', 'layout'),
      ('5 columns', 'columns:5'),
    ]) {
      final calls = <String>[];
      await _pump(tester, _bar(calls), 320);
      await tester.tap(find.byTooltip('More options'));
      await tester.pumpAndSettle();
      // On a short screen the menu scrolls; bring the row into view first.
      final scrollable = find.ancestor(
        of: find.text(label),
        matching: find.byType(Scrollable),
      );
      await tester.scrollUntilVisible(
        find.text(label),
        -100,
        scrollable: scrollable,
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text(label));
      await tester.pumpAndSettle();
      expect(calls, [expected], reason: 'row $label');
    }
  });

  testWidgets('the row never overflows, even with the longest sort label', (
    tester,
  ) async {
    // "Duration ↑" measures ~195dp against ~139dp for the short labels — the
    // tight case that decides where the filter chip must fold into the menu.
    for (final width in [460.0, 414.0, 400.0, 380.0, 375.0, 350.0, 320.0]) {
      for (final sort in ['date', 'duration']) {
        final calls = <String>[];
        await _pump(tester, _bar(calls, sort: sort), width);
        expect(
          tester.takeException(),
          isNull,
          reason: 'width $width, sort $sort must not overflow the row',
        );
      }
    }
  });

  testWidgets('a large system font does not overflow the row', (tester) async {
    // The system font size is a user setting; the width ladder divides by it
    // so the measured boundaries still hold when every label grows.
    for (final width in [320.0, 380.0, 400.0, 414.0, 460.0, 520.0, 540.0]) {
      final calls = <String>[];
      await _pump(tester, _bar(calls, sort: 'duration'), width, textScale: 1.3);
      expect(
        tester.takeException(),
        isNull,
        reason: 'width $width at 1.3x font must not overflow',
      );
    }
  });

  testWidgets('the overflow button stays on screen at accessibility font sizes', (
    tester,
  ) async {
    // iOS Dynamic Type reaches ~1.6x (AX1) to ~2x (AX2) with "larger
    // accessibility sizes" on, and the app does not disable text scaling. On a
    // small phone the sort chip would otherwise grow until the overflow button
    // — the only door to every control — is pushed off the edge.
    for (final (scale, width) in [
      (1.5, 320.0),
      (1.75, 320.0),
      (2.0, 320.0),
      (2.0, 360.0),
      (2.0, 400.0),
    ]) {
      final calls = <String>[];
      await _pump(
        tester,
        _bar(calls, sort: 'duration'),
        width,
        textScale: scale,
      );
      expect(
        tester.takeException(),
        isNull,
        reason: 'width $width at ${scale}x font must not overflow',
      );
      final rect = tester.getRect(find.byTooltip('More options'));
      expect(
        rect.right,
        lessThanOrEqualTo(width),
        reason: 'overflow button must stay on a ${width}dp screen at ${scale}x',
      );
    }
  });

  testWidgets('a long menu fits the screen and its last row is reachable', (
    tester,
  ) async {
    final calls = <String>[];
    await _pump(
      tester,
      _bar(
        calls,
        extensions: const [
          'mp4',
          'mkv',
          'avi',
          'mov',
          'webm',
          'ts',
          'flv',
          'wmv',
          'm4v',
        ],
      ),
      320,
      height: 700,
    );
    await tester.tap(find.byTooltip('More options'));
    await tester.pumpAndSettle();
    expect(
      tester.takeException(),
      isNull,
      reason: '19 menu rows must not extend past the screen',
    );

    final scrollable = find.ancestor(
      of: find.text('6 columns'),
      matching: find.byType(Scrollable),
    );
    expect(scrollable, findsOneWidget);
    await tester.scrollUntilVisible(
      find.text('6 columns'),
      -100,
      scrollable: scrollable,
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('6 columns'));
    await tester.pumpAndSettle();
    expect(calls, ['columns:6']);
  });

  testWidgets('a column range of one offers no column rows', (tester) async {
    final calls = <String>[];
    // The inline button is hidden for a one-value range (it would overwrite a
    // stored value without changing a pixel); the overflow must not reintroduce
    // that dead control. Sort direction is still a legitimate dropped control,
    // so the overflow button itself remains.
    await _pump(
      tester,
      MediaToolbar(
        sortOptions: const ['date'],
        currentSort: 'date',
        isAscending: true,
        onSortChanged: (_) {},
        onSortDirectionChanged: () {},
        currentColumns: 2,
        onColumnsChanged: (c) => calls.add('columns:$c'),
        minColumns: 2,
        maxColumns: 2,
      ),
      320,
    );
    await tester.tap(find.byTooltip('More options'));
    await tester.pumpAndSettle();
    expect(
      find.textContaining(RegExp(r'^\d+ columns?$')),
      findsNothing,
      reason: 'a one-value range cannot change anything',
    );
    expect(calls, isEmpty);
  });
}
