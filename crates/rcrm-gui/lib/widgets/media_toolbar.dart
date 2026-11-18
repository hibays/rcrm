// widgets/media_toolbar.dart
// RCrm GUI — sort / filter / display options toolbar
//
// Currently the video screen's toolbar: sort field dropdown, sort direction
// toggle, extension filter, column-count cycle button, and grid/list layout
// toggle.

import 'package:material_ui/material_ui.dart';

import '../utils/media_toolbar_layout.dart';
import 'column_button.dart';
import 'filter_tag_chip.dart';
import 'smart_popup_menu.dart';

/// The icon for each grouping, for the toolbar's button — the one place that has
/// to pick an icon at RUNTIME.
///
/// That is also the whole trouble with it: the release icon tree-shaker keeps a
/// glyph only when the `IconData` is a constant at a use site, which is why
/// `Icons.folder` has always rendered (eight files use it as a `const Icon`)
/// while `Icons.apps` and `Icons.category` — reachable here only through a
/// lookup — shipped as EMPTY GLYPHS. The grouping menu therefore writes its
/// three icons out as literals, and those literals are what keeps all three
/// glyphs in the font; this map is free to choose among them afterwards.
const Map<String, Icon> kGroupingIcons = {
  'none': Icon(Icons.apps, size: 16),
  'folder': Icon(Icons.folder, size: 16),
  'format': Icon(Icons.category, size: 16),
};

/// See [kGroupingIcons].
Icon groupingIcon(String grouping) =>
    kGroupingIcons[grouping] ?? kGroupingIcons['none']!;

/// Every row in the Organize menu, as a real type. The switch in
/// [MediaToolbar.build] is exhaustive over these three, so a new grouping
/// cannot be added without giving it a persisted value. Mirrors the codebase's
/// `MediaItemMenuAction` / `PlaybackMode` menus.
enum OrganizeAction { ungrouped, folder, format }

/// One row of the grouping menu: the check marking the arrangement in effect,
/// the icon, and the label.
///
/// The check's width is reserved whether or not it is drawn, so the three icons
/// sit in one column. `CheckedPopupMenuItem` would do the checking itself, but it
/// lays its title out through a `ListTile`, which overflows a popup menu's 280dp
/// as soon as the row carries an icon too.
///
/// The labels stay short for the same 280dp: with a check slot, an icon and two
/// gaps beside it, a wordy label overflows the row.
Widget _groupingRow(
  BuildContext context, {
  required bool selected,
  required Widget icon,
  required String label,
}) {
  return Row(
    children: [
      SizedBox(
        width: 16,
        child: selected
            ? Icon(
                Icons.check,
                size: 16,
                color: Theme.of(context).colorScheme.primary,
              )
            : null,
      ),
      const SizedBox(width: 8),
      icon,
      const SizedBox(width: 8),
      Text(label),
    ],
  );
}

class MediaToolbar extends StatelessWidget {
  final List<String> sortOptions;
  final String currentSort;
  final bool isAscending;
  final ValueChanged<String> onSortChanged;

  /// Flips the direction between ascending and descending.
  ///
  /// Separate from [onSortChanged], which commits a sort *field*: re-picking
  /// the field already active flips too (that rule lives in the provider — see
  /// `_SortNotifier.set`), but there the flip is the rule's outcome, not a
  /// direction contract. The arrow states the direction it wants, and being
  /// required keeps a caller from wiring an arrow that does nothing.
  final VoidCallback onSortDirectionChanged;

  final List<String>? extensions;
  final String? currentFilter;
  final ValueChanged<String>? onFilterChanged;

  final ValueChanged<int>? onColumnsChanged;
  final int? currentColumns;
  final int minColumns;
  final int maxColumns;

  /// Optional grid/list view toggle (rendered inline in the toolbar row).
  final bool? isGrid;
  final VoidCallback? onLayoutToggle;

  /// Optional grouping selector: what the list is ORGANIZED into — the video
  /// tab's flat / by-folder / by-format choice. Null hides it, like
  /// [onLayoutToggle], because the toolbar is shared with screens that have
  /// nothing to group by.
  ///
  /// A menu rather than a cycling button: three arrangements are not a sequence
  /// a user can predict from an icon, so the items say what they are.
  final String? currentGrouping;
  final ValueChanged<String>? onGroupingChanged;

  /// Optional chip on the toolbar's LEFT, beside the sort and format chips,
  /// showing/hiding the video tab's tag-filter row. Null hides it (screens
  /// without tags).
  ///
  /// A chip beside its siblings rather than a row buried in a menu: it is a
  /// first-class view control, and the bar below no longer spends 56dp of
  /// permanent space. The chip's selected state is the persisted preference,
  /// not whether the row happens to be visible right now — an active filter
  /// forces the row visible so it stays clearable.
  final bool? tagBarVisible;
  final VoidCallback? onToggleTagBar;

  const MediaToolbar({
    super.key,
    required this.sortOptions,
    required this.currentSort,
    required this.isAscending,
    required this.onSortChanged,
    required this.onSortDirectionChanged,
    this.extensions,
    this.currentFilter,
    this.onFilterChanged,
    this.onColumnsChanged,
    this.currentColumns,
    this.minColumns = 2,
    this.maxColumns = 6,
    this.isGrid,
    this.onLayoutToggle,
    this.currentGrouping,
    this.onGroupingChanged,
    this.tagBarVisible,
    this.onToggleTagBar,
  });

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (barContext, constraints) {
        // The bar follows the width it was GIVEN, not the window behind it:
        // a wide window can still hand this toolbar a narrow column. What that
        // width means is a pure rule in `utils/media_toolbar_layout.dart`,
        // tested at its boundaries instead of only through the rendered chip.
        final layout = mediaToolbarLayout(constraints.maxWidth);
        return _buildToolbar(barContext, layout: layout);
      },
    );
  }

  Widget _buildToolbar(
    BuildContext context, {
    required MediaToolbarLayout layout,
  }) {
    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: layout.horizontalPadding,
        vertical: 6,
      ),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          bottom: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: Row(
        children: [
          // Sort
          _sortChip(context),

          // Filter by extension
          if (extensions != null &&
              extensions!.isNotEmpty &&
              onFilterChanged != null) ...[
            const SizedBox(width: 8),
            _filterDropdown(context),
          ],

          // Tag-filter row toggle (optional): a sibling of the sort and format
          // chips on the LEFT, not a row buried in the Organize menu. The bar
          // below is opt-in so it no longer spends a permanent 56dp strip.
          if (onToggleTagBar != null) ...[
            const SizedBox(width: 8),
            _tagFilterChip(context, compact: layout.compactTagLabel),
          ],

          const Spacer(),

          // Column count toggle (cycles within [minColumns, maxColumns]) — no slider.
          // A grid pinch reaches the same setting, so this is the second
          // optional control to leave when the bar gets really tight.
          //
          // `maxColumns > minColumns` is not decoration: the caller passes the
          // range this WIDTH can display, and a narrow desktop window displays
          // exactly two whatever is stored. A cycle button whose range holds
          // one value cannot change anything the user sees, and tapping it
          // would still call back with that value — overwriting a stored 5 with
          // the 2 the window happened to allow. A control that cannot act is not
          // shown (Settings → Video Grid Columns is the door that survives).
          if (layout.showColumnButton &&
              onColumnsChanged != null &&
              currentColumns != null &&
              maxColumns > minColumns)
            ColumnButton(
              current: currentColumns!,
              min: minColumns,
              max: maxColumns,
              onChanged: onColumnsChanged!,
            ),

          // Sort direction. The icon reports the direction in effect, so it
          // agrees with the chip's arrow; the tooltip names what the tap does
          // (like the layout toggle below) and doubles as the semantics text.
          // First out at phone width: re-picking the active sort chip reverses
          // too, so this 40dp button has a door the Tag chip does not.
          if (layout.showSortArrow)
            IconButton(
              icon: Icon(
                isAscending ? Icons.arrow_upward : Icons.arrow_downward,
                size: 18,
              ),
              onPressed: onSortDirectionChanged,
              tooltip: isAscending ? 'Sort descending' : 'Sort ascending',
              visualDensity: VisualDensity.compact,
            ),

          // Grouping (optional): the button's icon reports the arrangement in
          // effect, so every item wears the SAME icon its own mode puts on the
          // button — otherwise the menu names three arrangements whose icons the
          // user can only see one of, and picking one looks like it changed the
          // icon to something the menu never offered. (The sort and filter menus
          // beside it carry no item icons, but their buttons do not change icon
          // with the selection either.)
          if (layout.showRightIcons &&
              currentGrouping != null &&
              onGroupingChanged != null)
            SmartPopupMenu<OrganizeAction>(
              tooltip: 'Organize',
              onSelected: (action) {
                // Each of the three rows maps to one classification. The enum
                // makes this exhaustive: a fourth row cannot be added without
                // saying what it does here.
                switch (action) {
                  case OrganizeAction.ungrouped:
                    onGroupingChanged?.call('none');
                  case OrganizeAction.folder:
                    onGroupingChanged?.call('folder');
                  case OrganizeAction.format:
                    onGroupingChanged?.call('format');
                }
              },
              items: [
                // Written out rather than looped over a label map, and each icon
                // a literal `const Icon`: the release icon tree-shaker keeps a
                // glyph only when its `IconData` reaches it as a constant at a
                // USE SITE, so an icon chosen through a lookup ships as an EMPTY
                // GLYPH — which is how the button and "By format" shipped blank
                // while the hardcoded `Icons.folder` in the sort menu rendered.
                // These three literals are what keeps all three glyphs in the
                // font; the button below may then pick among them at runtime.
                if (currentGrouping != null && onGroupingChanged != null) ...[
                  SmartPopupMenuItem(
                    value: OrganizeAction.ungrouped,
                    child: _groupingRow(
                      context,
                      selected: currentGrouping == 'none',
                      icon: const Icon(Icons.apps, size: 16),
                      label: 'Ungrouped',
                    ),
                  ),
                  SmartPopupMenuItem(
                    value: OrganizeAction.folder,
                    child: _groupingRow(
                      context,
                      selected: currentGrouping == 'folder',
                      icon: const Icon(Icons.folder, size: 16),
                      label: 'By folder',
                    ),
                  ),
                  SmartPopupMenuItem(
                    value: OrganizeAction.format,
                    child: _groupingRow(
                      context,
                      selected: currentGrouping == 'format',
                      icon: const Icon(Icons.category, size: 16),
                      label: 'By format',
                    ),
                  ),
                ],
              ],
              child: groupingIcon(currentGrouping!),
            ),

          // Grid/List layout toggle (optional); Settings → Display is its
          // other door, so it leaves before the left-side chips do.
          if (layout.showRightIcons && isGrid != null && onLayoutToggle != null)
            IconButton(
              icon: Icon(isGrid! ? Icons.list : Icons.grid_view, size: 18),
              onPressed: onLayoutToggle,
              tooltip: isGrid! ? 'List view' : 'Grid view',
              visualDensity: VisualDensity.compact,
            ),
        ],
      ),
    );
  }

  /// The tag-filter toggle. Face, border and label match its chip siblings;
  /// state lives only in the avatar slot ([TagToggleCheck] when on).
  Widget _tagFilterChip(BuildContext context, {required bool compact}) {
    final selected = tagBarVisible ?? false;
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    // Plain Chip siblings render on canvasColor, not surfaceContainer*.
    final neutral = theme.canvasColor;
    // Compact width drops the label; keep the name for screen readers.
    return Semantics(
      label: selected ? 'Hide tag filters' : 'Show tag filters',
      child: FilterChip(
        // OFF inherits the sibling chips' accent icon colour.
        avatar: selected ? TagToggleCheck() : const Icon(Icons.tag, size: 16),
        label: compact ? const SizedBox.shrink() : const Text('Tags'),
        labelPadding: compact ? EdgeInsets.zero : null,
        selected: selected,
        onSelected: (_) => onToggleTagBar?.call(),
        // Pin both states: M3's default flashes cyan mid-fade.
        color: WidgetStateProperty.all<Color?>(neutral),
        selectedColor: neutral,
        side: BorderSide(color: colors.outlineVariant),
        // M3's selected label ink is too dark on this face in Night.
        labelStyle: selected ? TextStyle(color: colors.onSurface) : null,
        // Built-in check would paint a near-black scrim over the avatar.
        showCheckmark: false,
        visualDensity: VisualDensity.compact,
        tooltip: selected ? 'Hide tag filters' : 'Show tag filters',
      ),
    );
  }

  Widget _sortChip(BuildContext context) {
    return SmartPopupMenu<String>(
      // The chip's own chrome shows the field and the direction in effect, and
      // the menu's check marks the field that is active — neither says what
      // re-picking that field does. The tooltip is where the rule is stated;
      // SmartPopupMenu feeds the same string to the control's semantics, so
      // it is announced and not merely hovered.
      tooltip:
          'Sort: ${_capitalize(currentSort)} ${isAscending ? '↑' : '↓'} — '
          'pick ${_capitalize(currentSort)} again to reverse',
      onSelected: onSortChanged,
      items: sortOptions
          .map(
            (opt) => SmartPopupMenuItem(
              value: opt,
              child: Row(
                children: [
                  if (opt == currentSort)
                    Icon(
                      Icons.check,
                      size: 16,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  const SizedBox(width: 8),
                  Text(_capitalize(opt)),
                ],
              ),
            ),
          )
          .toList(),
      child: Chip(
        avatar: const Icon(Icons.sort, size: 16),
        label: Text('${_capitalize(currentSort)} ${isAscending ? '↑' : '↓'}'),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  Widget _filterDropdown(BuildContext context) {
    final filterItems = <SmartPopupMenuItem<String>>[
      SmartPopupMenuItem(
        value: '',
        child: Row(
          children: [
            if (currentFilter == null || currentFilter!.isEmpty)
              Icon(
                Icons.check,
                size: 16,
                color: Theme.of(context).colorScheme.primary,
              ),
            const SizedBox(width: 8),
            const Text('All formats'),
          ],
        ),
      ),
    ];
    for (final ext in extensions!) {
      filterItems.add(
        SmartPopupMenuItem(
          value: ext,
          child: Row(
            children: [
              if (ext == currentFilter)
                Icon(
                  Icons.check,
                  size: 16,
                  color: Theme.of(context).colorScheme.primary,
                ),
              const SizedBox(width: 8),
              Text(ext.toUpperCase()),
            ],
          ),
        ),
      );
    }
    return SmartPopupMenu<String>(
      onSelected: (v) => onFilterChanged?.call(v),
      items: filterItems,
      child: Chip(
        avatar: const Icon(Icons.filter_list, size: 16),
        label: Text(
          currentFilter != null && currentFilter!.isNotEmpty
              ? currentFilter!.toUpperCase()
              : 'All',
        ),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  String _capitalize(String s) {
    if (s.isEmpty) return s;
    return '${s[0].toUpperCase()}${s.substring(1)}';
  }
}
