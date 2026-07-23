// widgets/media_toolbar.dart
// RCrm GUI — sort / filter / display options toolbar
//
// Shared toolbar for video and image screens. Provides sort
// dropdown, extension filter, grid column slider, and layout
// toggle.

import 'package:flutter/material.dart';
import 'column_button.dart';

class MediaToolbar extends StatelessWidget {
  final List<String> sortOptions;
  final String currentSort;
  final bool isAscending;
  final ValueChanged<String> onSortChanged;

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

          // Sort direction
          IconButton(
            icon: Icon(
              isAscending ? Icons.arrow_upward : Icons.arrow_downward,
              size: 18,
            ),
            onPressed: () => onSortChanged(currentSort),
            tooltip: isAscending ? 'Ascending' : 'Descending',
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
