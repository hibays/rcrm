// test/preview_controls_test.dart
// The preview's seek strip is the app's one scrub bar at thumbnail scale. It
// must lay out inside an ~81dp card without overflowing (the old media_kit
// default controls needed ~150dp and threw a RenderFlex error there), and its
// compact style/theming is pinned here so it cannot drift back to a bulky bar.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/widgets/player_scrub_bar.dart';
import 'package:rcrm_gui/widgets/preview_surface.dart';

void main() {
  testWidgets('the compact seek strip fits a thumbnail-sized card', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(145, 81));
    addTearDown(() => tester.binding.setSurfaceSize(null));

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SizedBox(
            width: 145,
            height: kPreviewStripHeight,
            child: PlayerScrubBar(
              value: 0.4,
              style: const ScrubBarStyle(track: 2.5, trackActive: 4, thumb: 4),
              activeColor: RCrmColors.playerAccent,
              thumbColor: RCrmColors.playerAccent,
              inactiveColor: RCrmColors.playerTrack,
              onChanged: (_) {},
            ),
          ),
        ),
      ),
    );
    await tester.pump();

    expect(tester.takeException(), isNull,
        reason: 'the seek bar must not overflow the preview card');
    expect(find.byType(PlayerScrubBar), findsOneWidget);
  });
}
