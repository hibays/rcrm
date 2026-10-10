// widgets/media_toolbar.dart
// RCrm GUI — sort / filter / display options toolbar
//
// Currently the video screen's toolbar: sort field dropdown, sort direction
// toggle, extension filter, column-count cycle button, and grid/list layout
// toggle.

import 'package:flutter/material.dart';
import 'column_button.dart';

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
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
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

          const Spacer(),

          // Column count toggle (cycles within [minColumns, maxColumns]) — no slider
          if (onColumnsChanged != null && currentColumns != null)
            ColumnButton(
              current: currentColumns!,
              min: minColumns,
              max: maxColumns,
              onChanged: onColumnsChanged!,
            ),

          // Sort direction. The icon reports the direction in effect, so it
          // agrees with the chip's arrow; the tooltip names what the tap does
          // (like the layout toggle below) and doubles as the semantics text.
          IconButton(
            icon: Icon(
              isAscending ? Icons.arrow_upward : Icons.arrow_downward,
              size: 18,
            ),
            onPressed: onSortDirectionChanged,
            tooltip: isAscending ? 'Sort descending' : 'Sort ascending',
            visualDensity: VisualDensity.compact,
          ),

          // Grid/List layout toggle (optional)
          if (isGrid != null && onLayoutToggle != null)
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

  Widget _sortChip(BuildContext context) {
    return PopupMenuButton<String>(
      // The chip's own chrome shows the field and the direction in effect, and
      // the menu's check marks the field that is active — neither says what
      // re-picking that field does. The tooltip is where the rule is stated;
      // PopupMenuButton feeds the same string to the control's semantics, so
      // it is announced and not merely hovered.
      tooltip:
          'Sort: ${_capitalize(currentSort)} ${isAscending ? '↑' : '↓'} — '
          'pick ${_capitalize(currentSort)} again to reverse',
      onSelected: onSortChanged,
      itemBuilder: (context) => sortOptions.map((opt) {
        return PopupMenuItem(
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
        );
      }).toList(),
      child: Chip(
        avatar: const Icon(Icons.sort, size: 16),
        label: Text('${_capitalize(currentSort)} ${isAscending ? '↑' : '↓'}'),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  Widget _filterDropdown(BuildContext context) {
    return PopupMenuButton<String>(
      onSelected: (v) => onFilterChanged?.call(v),
      itemBuilder: (context) {
        final items = <PopupMenuItem<String>>[
          PopupMenuItem(
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
          items.add(
            PopupMenuItem(
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
        return items;
      },
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
