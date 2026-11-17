// widgets/column_button.dart
// Compact column-count control: tap cycles within [min,max] (wraps), and
// hovering + mouse wheel steps by one (up = more, down = fewer). Replaces the
// old Size slider; shared by the video toolbar and the image album view.
//
// [min] and [max] are what the CURRENT width can display, not a constant range,
// so they can collapse to a single value on a narrow window. In that case the
// control neither acts (see `_cycle`) nor is built by the toolbar: a button
// showing the only number available is a control that cannot act.

import 'package:flutter/gestures.dart';
import 'package:material_ui/material_ui.dart';

class ColumnButton extends StatelessWidget {
  final int current;
  final int min;
  final int max;
  final ValueChanged<int> onChanged;

  const ColumnButton({
    super.key,
    required this.current,
    required this.onChanged,
    this.min = 2,
    this.max = 6,
  });

  /// Wrap to [min] at the top. A range that holds ONE value has nothing to
  /// cycle, so a tap must not emit anything: the caller's range is what the
  /// current width can DISPLAY, and writing it back would replace the user's
  /// stored choice (6 columns) with the number the window happened to allow
  /// (2) without changing a single pixel on screen.
  void _cycle() {
    if (max <= min) return;
    onChanged(current >= max ? min : current + 1);
  }

  void _step(int d) {
    if (max <= min) return;
    final n = (current + d).clamp(min, max);
    if (n != current) onChanged(n);
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      onPointerSignal: (s) {
        if (s is PointerScrollEvent && s.scrollDelta.dy != 0) {
          _step(s.scrollDelta.dy < 0 ? -1 : 1); // wheel up = fewer, down = more
        }
      },
      child: Tooltip(
        message: 'Columns: $current',
        child: TextButton(
          onPressed: _cycle,
          style: TextButton.styleFrom(
            visualDensity: VisualDensity.compact,
            padding: const EdgeInsets.symmetric(horizontal: 8),
            minimumSize: const Size(0, 32),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.view_column, size: 16),
              const SizedBox(width: 3),
              Text('$current'),
            ],
          ),
        ),
      ),
    );
  }
}
