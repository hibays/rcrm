// test/video_card_semantics_test.dart
// The inline hover preview must never contribute semantics nodes.
//
// Hovering a video card mounts a media_kit Video with its whole control stack
// (buttons, focus nodes, animated opacities) and unmounts it again when the
// pointer moves to the next card. On Windows the engine mirrors every semantics
// change into a ui::AXTree; a node removed while an update is still being
// serialized desyncs it and logs "N will not be in the tree and is not the new
// root" (flutter/flutter#182444). A transient thumbnail is decorative, so the
// preview sits behind one stable ExcludeSemantics boundary.
//
// The real Video needs native media_kit libraries the widget test VM does not
// have, so this pins the boundary through PreviewSurface's stand-in child.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/preview_surface.dart';
import 'package:rcrm_gui/widgets/video_card.dart';

void main() {
  setUp(() => ThumbnailService.debugPosterLoader = ThumbnailService.noPoster);
  tearDown(() => ThumbnailService.debugPosterLoader = null);

  testWidgets('the poster side of the hover switch is hidden too', (
    tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: VideoCard(
            item: MediaItem(
              name: 'N.mkv',
              path: '/movies/night.mkv',
              url: 'http://127.0.0.1:8080/movies/night.mkv',
              type: MediaType.video,
            ),
          ),
        ),
      ),
    );
    await tester.pump();

    // Swapping to the poster must not create a node either: its loading
    // spinner is a semantics node of its own, and that single node per hover
    // was enough to desync the Windows AXTree once the bridge was corrupted.
    expect(
      find.descendant(
        of: find.byType(VideoCard),
        matching: find.byType(ExcludeSemantics),
      ),
      findsWidgets,
    );
  });


  testWidgets('the preview subtree is hidden from the semantics tree', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: PreviewSurface(
            frameReady: false,
            active: true,
            poster: SizedBox.shrink(),
            video: Text('preview clip'),
            withSeek: false,
          ),
        ),
      ),
    );
    await tester.pump();

    // The picture is still painted and the boundary wraps the preview...
    expect(find.text('preview clip'), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(PreviewSurface),
        matching: find.byType(ExcludeSemantics),
      ),
      findsOneWidget,
    );

    // ...but a screen reader never sees a node for it. Without the boundary a
    // Text carries its label into the semantics tree and the AXTree churn that
    // triggers the Windows error returns.
    expect(find.bySemanticsLabel('preview clip'), findsNothing);

    semantics.dispose();
  });
}
