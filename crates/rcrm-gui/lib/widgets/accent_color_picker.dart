// widgets/accent_color_picker.dart
// Appearance → Accent → Custom. The one door to the picker, kept in its own
// file so the Settings screen does not import a third-party colour model.

import 'package:flutter_colorpicker/flutter_colorpicker.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
// flutter_colorpicker builds against `package:flutter/material.dart`, while the
// app uses the 3.50 `material_ui` fork. They are DIFFERENT Material/ThemeData
// classes, so the picker's own widgets need a shim: a transparent flutter
// Material ancestor (and an empty labelTypes, which drops its DropdownButton —
// there is no Navigator inside the SmartDialog overlay).
// ignore: deprecated_member_use — the picker is built against flutter/material
import 'package:flutter/material.dart' as fm;
import 'package:flutter/widgets.dart' as fw;
import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';

Color _opaque(Color c) => Color.fromARGB(
  255,
  (c.r * 255).round().clamp(0, 255),
  (c.g * 255).round().clamp(0, 255),
  (c.b * 255).round().clamp(0, 255),
);

/// Opens the colour picker and returns the chosen opaque ARGB, or null when the
/// dialog was cancelled/dismissed. Nothing is persisted here — the caller owns
/// the one committing action (`uiSettingsProvider.setAppearanceCustomColor`).
///
/// SmartDialog is used instead of `showDialog` for the same reason the other
/// transient surfaces are: the overlay lives above the Navigator, so the
/// picker cannot be stranded by a route change while it is open. It needs no
/// Navigator ancestor of its own.
Future<Color?> showAccentColorPicker({
  required BuildContext context,
  required Color initialColor,
}) async {
  var picked = _opaque(initialColor);
  return SmartDialog.show<Color>(
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setState) => AlertDialog(
        title: const Text('Custom accent'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Choose a colour for actions, progress and selection. It is '
                'checked against both canvases so it stays readable in Day '
                'and Night.',
                style: TextStyle(
                  color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                  fontSize: 13,
                ),
              ),
              const SizedBox(height: 12),
              Center(
                // The picker has no Navigator or flutter Material/Theme above
                // it (SmartDialog overlay + the material_ui fork), so shim all
                // three below: a portrait MediaQuery (its landscape branch needs
                // ~560dp and would overflow a phone), flutter's localizations
                // for the hex TextField, and a transparent flutter Material
                // ancestor. labelTypes is empty so its DropdownButton — which
                // pushes a route — is never built.
                //
                // The whole shim is laid out at a fixed 280x300 (the picker's
                // own widths are constants), then FittedBox scales it down when
                // the dialog is narrower than that — a 320dp phone gives the
                // dialog only ~192dp of content width. Without this the palette
                // is clipped and the hex row overflows on small screens.
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  child: SizedBox(
                    width: 280,
                    height: 300,
                    child: MediaQuery(
                      data: MediaQuery.of(ctx)
                          .copyWith(size: const Size(320, 560)),
                      child: Localizations(
                        locale:
                            Localizations.maybeLocaleOf(ctx) ??
                            const Locale('en'),
                        delegates: const [
                          fw.DefaultWidgetsLocalizations.delegate,
                          fm.DefaultMaterialLocalizations.delegate,
                        ],
                        child: fm.Material(
                          type: fm.MaterialType.transparency,
                          child: ColorPicker(
                            pickerColor: picked,
                            onColorChanged: (c) => setState(() {
                              // The accent is always opaque; alpha has no meaning
                              // on a theme colour and would make the derived
                              // shades ambiguous.
                              picked = _opaque(c);
                            }),
                            enableAlpha: false,
                            hexInputBar: true,
                            labelTypes: const [],
                            colorPickerWidth: 270,
                            pickerAreaHeightPercent: 0.62,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              _DerivedPreview(color: picked),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => SmartDialog.dismiss(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => SmartDialog.dismiss(result: picked),
            child: const Text('Use this colour'),
          ),
        ],
      ),
    ),
  );
}

/// Shows the two shades the app will actually paint: the picked colour lifted
/// until it reads on black, and deepened until it reads on cream. A picker
/// that only showed the raw swatch would promise a colour the app never uses.
class _DerivedPreview extends StatelessWidget {
  final Color color;
  const _DerivedPreview({required this.color});

  @override
  Widget build(BuildContext context) {
    final entries = <(String, Color)>[
      ('Night', RCrmTheme.customDark(color)),
      ('Day', RCrmTheme.customLight(color)),
    ];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Readable variants',
          style: Theme.of(context).textTheme.bodyMedium,
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            for (final (label, shade) in entries) ...[
              Expanded(
                child: Container(
                  height: 44,
                  decoration: BoxDecoration(
                    color: shade,
                    borderRadius: BorderRadius.circular(RCrmRadii.sm),
                  ),
                  alignment: Alignment.center,
                  child: Text(
                    label,
                    style: TextStyle(
                      color: shade.computeLuminance() > 0.5
                          ? const Color(0xFF101010)
                          : const Color(0xFFFFFFFF),
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ),
              if (label != entries.last.$1) const SizedBox(width: 8),
            ],
          ],
        ),
      ],
    );
  }
}
