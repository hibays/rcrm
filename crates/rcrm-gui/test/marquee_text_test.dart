// test/marquee_text_test.dart
// The scrolling title must stay a seamless loop: the inner viewport that gives
// the row its intrinsic width must NOT clip it. Clipping there cuts the second
// copy off at the right edge and the loop ends with a gap (the regression
// fixed 2026-11-17).

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/widgets/marquee_text.dart';

void main() {
  testWidgets(
    'a long title overflows without an error, and the viewport does not clip',
    (tester) async {
      await tester.binding.setSurfaceSize(const Size(320, 200));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Center(
              child: SizedBox(
                width: 120,
                child: MarqueeText(
                  text: 'a very long title that must scroll forever and ever',
                ),
              ),
            ),
          ),
        ),
      );
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 50));

      expect(tester.takeException(), isNull);
      final viewport = tester.widget<SingleChildScrollView>(
        find.byType(SingleChildScrollView),
      );
      expect(
        viewport.clipBehavior,
        Clip.none,
        reason: 'the inner viewport must not cut the loop seam',
      );

      await tester.pump(const Duration(milliseconds: 500));
      expect(tester.takeException(), isNull);
    },
  );
}
