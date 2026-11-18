// test/tag_toggle_check_test.dart
// The Tags toggle's ON avatar: palette and contrast in both appearances,
// for every accent.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/widgets/filter_tag_chip.dart';

double _contrast(Color a, Color b) {
  final la = a.computeLuminance();
  final lb = b.computeLuminance();
  return (la > lb ? la + 0.05 : lb + 0.05) / (la > lb ? lb + 0.05 : la + 0.05);
}

void main() {
  for (final accent in RCrmAccent.values) {
    testWidgets('$accent check keeps its contrast in both appearances', (
      tester,
    ) async {
      for (final brightness in Brightness.values) {
        // Plain Theme: AnimatedTheme would be mid-transition on pass two.
        final theme = RCrmTheme.build(accent: accent, brightness: brightness);
        final scheme = theme.colorScheme;
        await tester.pumpWidget(
          Directionality(
            textDirection: TextDirection.ltr,
            child: Theme(
              data: theme,
              child: Center(child: TagToggleCheck(key: ValueKey(brightness))),
            ),
          ),
        );

        final check = tester.widget<Icon>(
          find.descendant(
            of: find.byType(TagToggleCheck),
            matching: find.byIcon(Icons.check),
          ),
        );
        final fadedTag = tester.widget<Icon>(
          find.descendant(
            of: find.byType(TagToggleCheck),
            matching: find.byIcon(Icons.tag),
          ),
        );

        expect(check.color, scheme.primary);
        expect(fadedTag.color, scheme.onSurface.withValues(alpha: 0.2));
        expect(fadedTag.size, 13);
        expect(
          check.size,
          greaterThan(fadedTag.size!),
          reason: '$accent / $brightness: the state mark must dominate the `#`',
        );

        // AA body-text contrast on the chip face.
        expect(
          _contrast(check.color!, theme.canvasColor),
          greaterThanOrEqualTo(4.5),
          reason: '$accent / $brightness: the check itself must read',
        );
      }
    });
  }
}
