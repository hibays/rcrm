// test/video_keyword_filter_test.dart
// The video tab's keyword row, end to end: the tags come from the file names,
// the chips filter the grid (multi-select narrows with ALL), and All clears.

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/keyword_provider.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/video_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/column_button.dart';
import 'package:rcrm_gui/widgets/keyword_filter_bar.dart';
import 'package:rcrm_gui/widgets/video_card.dart';

MediaItem _video(String name, {String folder = ''}) => MediaItem(
  name: folder.isEmpty ? name : '$folder/$name',
  path: folder.isEmpty ? '/$name' : '/$folder/$name',
  url: 'http://127.0.0.1:18443/${folder.isEmpty ? '' : '$folder/'}$name',
  type: MediaType.video,
  size: 1024,
  durationSeconds: 60,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

final _one = _video('one.mp4', folder: 'Amateur');
final _two = _video('two.mp4', folder: 'Amateur');
final _three = _video('three.mp4', folder: 'Cooking');

List<String> _names(WidgetTester tester) => tester
    .widgetList<VideoCard>(find.byType(VideoCard))
    .map((c) => c.item.name)
    .toList();

/// The bar is opt-in now, so the two filter tests below ask for it up front;
/// the toggle itself is covered separately. An override keeps the state in the
/// container instead of writing a preference the next test would inherit.
class _TagBarSettings extends SettingsNotifier {
  _TagBarSettings();

  @override
  SettingsState build() => const SettingsState(videoTagBarVisible: true);
}

/// The quiet rules (folders are channels, no repeated tags yet) must not
/// swallow an explicit opt-in: a checked chip with no bar is a dead switch.
class _FolderTagBarSettings extends SettingsNotifier {
  _FolderTagBarSettings();

  @override
  SettingsState build() => const SettingsState(videoClassification: 'folder');
}

Future<ProviderContainer> _pump(
  WidgetTester tester,
  List<MediaItem> videos, {
  bool showTagBar = false,
  Size surfaceSize = const Size(1000, 800),
  SettingsNotifier Function()? settingsOverride,
}) async {
  await tester.binding.setSurfaceSize(surfaceSize);
  addTearDown(() => tester.binding.setSurfaceSize(null));
  final override =
      settingsOverride ?? (showTagBar ? () => _TagBarSettings() : null);
  final c = ProviderContainer(
    overrides: override == null
        ? const []
        : [uiSettingsProvider.overrideWith(override)],
  );
  addTearDown(c.dispose);
  c.read(videosMapProvider.notifier).addAll(videos);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: const Scaffold(body: VideoScreen()),
      ),
    ),
  );
  await tester.pump();
  return c;
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbnailService.debugPosterLoader = ThumbnailService.noPoster;
  });
  tearDown(() => ThumbnailService.debugPosterLoader = null);

  testWidgets('a repeated name word becomes a chip that filters the grid', (
    tester,
  ) async {
    final c = await _pump(tester, [_one, _two, _three], showTagBar: true);

    // Two files carry Amateur; Cooking is a one-off and is therefore not a
    // filter. `All tags` is always there.
    expect(find.byType(KeywordFilterBar), findsOneWidget);
    expect(find.text('Amateur'), findsOneWidget);
    expect(find.text('Cooking'), findsNothing);
    expect(_names(tester), hasLength(3));

    await tester.tap(find.text('Amateur'));
    await tester.pump();
    expect(_names(tester), ['Amateur/one.mp4', 'Amateur/two.mp4']);
    expect(c.read(videoTagFilterProvider), {'amateur'});

    await tester.tap(
      find.descendant(
        of: find.byType(KeywordFilterBar),
        matching: find.text('All tags'),
      ),
    );
    await tester.pump();
    expect(_names(tester), hasLength(3));
    expect(c.read(videoTagFilterProvider), isEmpty);
  });

  testWidgets('the bar is hidden by default and the toolbar Tags chip turns '
      'it on, where it persists', (tester) async {
    final c = await _pump(tester, [_one, _two, _three]);

    // No bar means no 56dp strip spent on a filter the user never asked for.
    expect(find.byType(KeywordFilterBar), findsNothing);
    expect(find.text('Amateur'), findsNothing);

    // The toggle is a chip beside sort/format on the toolbar's left, not a row
    // buried in the Organize menu.
    final chip = find.widgetWithText(FilterChip, 'Tags');
    expect(chip, findsOneWidget);
    final chipBox = tester.widget<FilterChip>(chip);
    expect(chipBox.selected, isFalse);
    // The chip's FACE is identical in both states: no ON wash, no coloured
    // patch. FilterChip's DEFAULT `color` (M3 secondaryContainer = cyan when
    // selected, which outranks selectedColor) is pinned to the same neutral
    // its two sibling chips wear. State lives in the icon slot only.
    final scheme = Theme.of(tester.element(chip)).colorScheme;
    expect(chipBox.color, isNotNull);
    final off = chipBox.color!.resolve(<WidgetState>{});
    final on = chipBox.color!.resolve({WidgetState.selected});
    expect(off, scheme.surfaceContainerLow);
    expect(on, off);
    expect(chipBox.selectedColor, off);
    // The tag glyph is a SIBLING before it is a state: OFF it inherits the
    // chip's own icon colour, which is exactly what the sort and format avatars
    // beside it resolve to, so the third chip does not read as permanently
    // dimmed. The state only takes the accent back once the check lands.
    expect(chipBox.avatar, isA<Icon>());
    expect(
      (chipBox.avatar as Icon).color,
      isNull,
      reason: 'OFF must inherit the sibling chips\' icon colour, not dim it',
    );
    final tagInk = IconTheme.of(
      tester.element(
        find.descendant(of: chip, matching: find.byIcon(Icons.tag)),
      ),
    ).color;
    final sortInk = IconTheme.of(tester.element(find.byIcon(Icons.sort))).color;
    expect(tagInk, sortInk, reason: 'same colour as the other chips');
    expect(tagInk, scheme.primary);
    expect(chipBox.showCheckmark, isTrue);
    expect(chipBox.checkmarkColor, scheme.primary);
    // OFF inherits the sibling chips' default label; ON must override it with
    // the page's primary ink — M3's default selected label is a DARK ink that
    // is unreadable on this chip's neutral surface in the Night appearance.
    expect(chipBox.labelStyle, isNull);

    await tester.tap(chip);
    await tester.pump();
    // The bar mounts a horizontal ListView and its chips' own state
    // animations; give them a frame of real time so nothing is left pending at
    // teardown. (Chip labels are plain, ellipsised `Text` since the shared
    // `FilterTagChip` — no marquee ticker in here.)
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump(const Duration(milliseconds: 50));

    expect(find.byType(KeywordFilterBar), findsOneWidget);
    expect(c.read(uiSettingsProvider).videoTagBarVisible, isTrue);
    // ON hands the accent over to the check: the glyph itself steps back to
    // faint grey (FilterChip paints the primary check OVER it), the chip face
    // and the label box stay put.
    final onChip = tester.widget<FilterChip>(chip);
    expect(onChip.label, isA<Text>());
    expect((onChip.label as Text).data, 'Tags');
    expect(onChip.avatar, isA<Icon>());
    expect((onChip.avatar as Icon).color, RCrmColors.textFaint);
    expect(
      (onChip.avatar as Icon).color,
      isNot(sortInk),
      reason: 'the checked glyph must not keep competing with its own check',
    );
    expect(onChip.labelStyle?.color, scheme.onSurface);
    // Ink on the (unchanged) neutral face still passes AA (≥4.5:1 for body
    // text).
    final onSurface = onChip.color!.resolve({WidgetState.selected})!;
    final lInk = scheme.onSurface.computeLuminance();
    final lBg = onSurface.computeLuminance();
    final ratio =
        (lInk > lBg ? lInk + 0.05 : lBg + 0.05) /
        (lInk > lBg ? lBg + 0.05 : lInk + 0.05);
    expect(ratio, greaterThanOrEqualTo(4.5));
    expect(
      await SettingsService().getVideoTagBarVisible(),
      isTrue,
      reason: 'the choice has to survive a relaunch, like grouping does',
    );
    // Tapping the chip did not change the arrangement.
    expect(c.read(uiSettingsProvider).videoClassification, 'none');
  });

  testWidgets('an explicit Tags opt-in shows the bar even in folder view', (
    tester,
  ) async {
    await _pump(tester, [
      _one,
      _two,
    ], settingsOverride: _FolderTagBarSettings.new);

    final chip = find.widgetWithText(FilterChip, 'Tags');
    expect(chip, findsOneWidget);
    expect(find.byType(KeywordFilterBar), findsNothing);

    await tester.tap(chip);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump(const Duration(milliseconds: 50));

    // Folders being channels is a DEFAULT quiet rule, not a veto of a control
    // the user just pressed: a checked chip must have something to hide.
    final on = tester.widget<FilterChip>(chip);
    expect(on.selected, isTrue);
    expect(on.tooltip, 'Hide tag filters');
    expect(find.byType(KeywordFilterBar), findsOneWidget);
  });

  testWidgets('the Tags chip follows the toolbar width, not a guessed window '
      'width', (tester) async {
    await _pump(tester, [
      _one,
      _two,
      _three,
    ], surfaceSize: const Size(414, 800));

    FilterChip chipAt() => tester.widget<FilterChip>(
      find.byWidgetPredicate(
        (w) => w is FilterChip && w.tooltip == 'Show tag filters',
      ),
    );

    // At a phone width the chip is still the third left-side sibling, but the
    // label and its padding are gone; the avatar and tooltip still name it.
    var chip = chipAt();
    expect(chip.label, isA<SizedBox>());
    expect((chip.label as SizedBox).width, 0);
    expect(chip.labelPadding, EdgeInsets.zero);
    expect(chip.avatar, isNotNull);
    // The 40dp sort arrow has a second door (re-picking the active sort chip),
    // so it is the first optional control the narrow bar gives up.
    expect(find.byTooltip('Sort descending'), findsNothing);
    expect(
      tester.takeException(),
      isNull,
      reason: 'a phone-width toolbar must not overflow',
    );

    // Grow the surface: LayoutBuilder re-measures the BAR it was given, so the
    // label and the arrow return without this test knowing a window breakpoint.
    await tester.binding.setSurfaceSize(const Size(800, 800));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump(const Duration(milliseconds: 50));
    chip = chipAt();
    expect(chip.label, isA<Text>());
    expect((chip.label as Text).data, 'Tags');
    expect(chip.labelPadding, isNull);
    expect(find.byTooltip('Sort descending'), findsOneWidget);

    // The same ladder keeps going instead of overflowing: the two right-side
    // menus (both have Settings rows) leave at 375dp, then the column button
    // at 320dp. The Tags chip itself never leaves.
    //
    // The column button is NOT asserted at 375 or 414 here: this harness shrinks
    // the SURFACE, not the window, so `MediaQuery.sizeOf` still reports the
    // default 800 and the range the screen hands the bar stays 2..5 — a state
    // production cannot reach (a 375dp window displays (2,2), and a range that
    // holds one value is not built at all). `column_button_test.dart` pins that
    // rule where the range can be stated directly.
    await tester.binding.setSurfaceSize(const Size(375, 800));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.byTooltip('Organize'), findsNothing);
    expect(chipAt().avatar, isNotNull);
    expect(tester.takeException(), isNull);

    await tester.binding.setSurfaceSize(const Size(320, 800));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    await tester.pump(const Duration(milliseconds: 50));
    expect(find.byType(ColumnButton), findsNothing);
    expect(find.byTooltip('List view'), findsNothing);
    expect(chipAt().avatar, isNotNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('a filter from elsewhere brings the hidden bar back so it can '
      'be cleared', (tester) async {
    final c = await _pump(tester, [_one, _two, _three]);
    expect(find.byType(KeywordFilterBar), findsNothing);

    // A Home channel / tag search selects a tag without touching this toggle.
    c.read(videoTagFilterProvider.notifier).toggle('amateur');
    await tester.pump();

    expect(find.byType(KeywordFilterBar), findsOneWidget);
    expect(_names(tester), ['Amateur/one.mp4', 'Amateur/two.mp4']);

    await tester.tap(
      find.descendant(
        of: find.byType(KeywordFilterBar),
        matching: find.text('All tags'),
      ),
    );
    await tester.pump();
    // Clearing the last filter returns the space to the list.
    expect(c.read(videoTagFilterProvider), isEmpty);
    expect(find.byType(KeywordFilterBar), findsNothing);
  });

  testWidgets('the empty state names the format filter and its one action '
      'clears it too', (tester) async {
    // The tag lives on MKV files only, so asking for MP4 empties the list
    // WITHOUT the tags being the whole story.
    final c = await _pump(
      tester,
      [
        _video('beach one.mkv', folder: 'Amateur'),
        _video('beach two.mkv', folder: 'Amateur'),
        _video('indoor three.mp4', folder: 'Amateur'),
      ],
      showTagBar: true,
    );

    await tester.tap(find.text('Beach'));
    await tester.pump();
    c.read(videoFilterProvider.notifier).set('mp4');
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    expect(
      find.text('No MP4 videos tagged “Beach”'),
      findsOneWidget,
      reason: 'the format is part of why the list is empty',
    );
    expect(find.text('Clear filter'), findsOneWidget);

    // The button promises a non-empty list, so it cannot stop at the tags.
    await tester.tap(find.text('Clear filter'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(c.read(videoTagFilterProvider), isEmpty);
    expect(c.read(videoFilterProvider), isEmpty);
    expect(_names(tester), hasLength(3));
  });

  testWidgets('two selected chips narrow to the files carrying BOTH tags', (
    tester,
  ) async {
    final aa1 = _video('aa one.mp4', folder: 'a');
    final aa2 = _video('aa two.mp4', folder: 'a');
    final bb1 = _video('bb one.mp4', folder: 'b');
    final bb2 = _video('bb two.mp4', folder: 'b');
    final both = _video('aa bb.mp4', folder: 'c');
    final c = await _pump(tester, [aa1, aa2, bb1, bb2, both], showTagBar: true);

    expect(find.text('Aa'), findsOneWidget);
    expect(find.text('Bb'), findsOneWidget);

    await tester.tap(find.text('Aa'));
    await tester.pump();
    expect(_names(tester).length, 3);
    expect(c.read(videoTagFilterProvider), {'aa'});

    await tester.tap(find.text('Bb'));
    await tester.pump();
    expect(_names(tester), ['c/aa bb.mp4']);
    expect(c.read(videoTagFilterProvider), {'aa', 'bb'});

    await tester.tap(
      find.descendant(
        of: find.byType(KeywordFilterBar),
        matching: find.text('All tags'),
      ),
    );
    await tester.pump();
    expect(_names(tester), hasLength(5));
  });
}
