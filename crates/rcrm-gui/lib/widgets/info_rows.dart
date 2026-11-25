// widgets/info_rows.dart
//
// The two primitives every media info panel is built from: a labelled row (icon,
// label, optional right-aligned value) and a hairline rule. Shared so the image
// viewer's panel and the item menu's video panel read as one surface — the
// alternative was two private copies that would drift the first time either was
// touched.

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';
import '../config/theme.dart';


/// The grabber at the top of a bottom sheet. It LOOKS like the standard
/// swipe-to-dismiss handle, so it must actually dismiss: a decorative strip
/// that promises a gesture and does nothing is the dead-control defect. Both
/// a downward flick AND a slow deliberate drag (>40dp) close the sheet, and a
/// tap on the handle closes it too — a flick-only handle is dead for anyone
/// who drags slowly. All dismissals use `SmartStatus.dialog` so a visible
/// notify never eats the gesture.
class InfoGrabber extends StatefulWidget {
  const InfoGrabber({super.key});

  @override
  State<InfoGrabber> createState() => _InfoGrabberState();
}

class _InfoGrabberState extends State<InfoGrabber> {
  double? _startY;
  double _dragged = 0;

  void _close() => SmartDialog.dismiss(status: SmartStatus.dialog);

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SizedBox(
        height: 44,
        width: double.infinity,
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onVerticalDragStart: (d) {
            _startY = d.globalPosition.dy;
            _dragged = 0;
          },
          onVerticalDragUpdate: (d) {
            if (_startY == null) return;
            _dragged = d.globalPosition.dy - _startY!;
          },
          onVerticalDragEnd: (d) {
            final flick = (d.primaryVelocity ?? 0) > 200;
            if (flick || _dragged > 40) _close();
            _startY = null;
            _dragged = 0;
          },
          onTap: _close,
          child: Center(
            child: Container(
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: RCrmColors.textFaint,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// One labelled fact: icon, label, and — when there is one — a value that may
/// give way. Both sides are long in practice (folder paths, author names), so
/// the value is flexible and never overflows.
class InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String? value;

  const InfoRow({
    super.key,
    required this.icon,
    required this.label,
    this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        children: [
          Icon(icon, size: 19, color: RCrmColors.textSecondary),
          const SizedBox(width: 14),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                color: RCrmColors.textPrimary,
                fontSize: 14,
                height: 1.3,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (value != null) ...[
            const SizedBox(width: 12),
            Flexible(
              child: Text(
                value!,
                style: TextStyle(color: RCrmColors.textSecondary, fontSize: 13),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                textAlign: TextAlign.end,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

/// The panel's divider. It has to be ink-on-cream in Day and white-on-ash in
/// Night, so it reads the semantic hairline token rather than a fixed hex.
class InfoRule extends StatelessWidget {
  const InfoRule({super.key});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 14),
    child: Divider(height: 1, thickness: 1, color: RCrmColors.hairline),
  );
}
