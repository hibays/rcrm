// test/preview_surface_test.dart
// PreviewSurface is a pure view of the whole inline-preview stack. Contract:
//  * the poster is mounted ONCE at a fixed index and stays underneath
//  * the Video sits above it and fades IN (opacity 0 -> 1) once a frame is ready
//  * before a frame, opacity 0 so the POSTER (not the card background) shows
//  * everything is inside one stable ExcludeSemantics boundary
//  * the tap layer / seek strip keep working across the fade

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import 'package:rcrm_gui/widgets/preview_surface.dart';

const kVideo = Key('preview-video');
const kPoster = Key('preview-poster');

Widget _host({
  required bool frameReady,
  bool active = true,
  bool withSeek = false,
}) {
  return MaterialApp(
    home: Scaffold(
      body: SizedBox(
        width: 160,
        height: 90,
        child: PreviewSurface(
          frameReady: frameReady,
          active: active,
          poster: const SizedBox(key: kPoster),
          video: const SizedBox(key: kVideo),
          player: null, // no native Player in the widget test VM
          withSeek: withSeek,
        ),
      ),
    ),
  );
}

AnimatedOpacity _videoFade(WidgetTester tester) => tester.widget<AnimatedOpacity>(
  find.ancestor(
    of: find.byKey(kVideo),
    matching: find.byType(AnimatedOpacity),
  ),
);

void main() {
  testWidgets('poster is the persistent bottom layer, video above it', (
    tester,
  ) async {
    await tester.pumpWidget(_host(frameReady: false));
    expect(find.byKey(kPoster), findsOneWidget);
    expect(find.byKey(kVideo), findsOneWidget);

    final stack = tester.widget<Stack>(
      find.ancestor(of: find.byKey(kPoster), matching: find.byType(Stack)),
    );
    expect(stack.children[0], isA<IgnorePointer>(),
        reason: 'the bottom layer is the hit-transparent poster');
    expect(stack.children[1], isA<AnimatedOpacity>(),
        reason: 'the fading video layer sits above the poster');
  });

  testWidgets('before a frame the video is transparent, showing the poster', (
    tester,
  ) async {
    await tester.pumpWidget(_host(frameReady: false));
    final fade = _videoFade(tester);
    expect(fade.opacity, 0.0);
    // A transparent fill on the real Video is what lets the poster through;
    // the view contract here is that the fade starts fully transparent.
  });

  testWidgets('once a frame is ready the video fades IN to opacity 1', (
    tester,
  ) async {
    await tester.pumpWidget(_host(frameReady: false));
    await tester.pumpWidget(_host(frameReady: true));
    await tester.pump(const Duration(milliseconds: 300));
    expect(_videoFade(tester).opacity, 1.0);
  });

  testWidgets('inactive snaps video transparent with no fade', (tester) async {
    await tester.pumpWidget(_host(frameReady: true, active: false));
    final fade = _videoFade(tester);
    expect(fade.opacity, 0.0);
    expect(fade.duration, Duration.zero);
  });

  testWidgets('the poster is the same element across the fade (no remount)', (
    tester,
  ) async {
    await tester.pumpWidget(_host(frameReady: false));
    final before = tester.element(find.byKey(kPoster));
    await tester.pumpWidget(_host(frameReady: true));
    await tester.pump(const Duration(milliseconds: 300));
    final after = tester.element(find.byKey(kPoster));
    expect(identical(before, after), isTrue,
        reason: 'poster must not remount when the video fades in');
  });

  testWidgets('the whole preview is one ExcludeSemantics boundary', (
    tester,
  ) async {
    await tester.pumpWidget(_host(frameReady: false));
    expect(
      find.descendant(
        of: find.byType(PreviewSurface),
        matching: find.byType(ExcludeSemantics),
      ),
      findsOneWidget,
    );
  });

  testWidgets('the poster ignores hits so the tap layer receives them', (
    tester,
  ) async {
    await tester.pumpWidget(_host(frameReady: false));
    final stack = tester.widget<Stack>(
      find.ancestor(of: find.byKey(kPoster), matching: find.byType(Stack)),
    );
    final ignore = stack.children[0] as IgnorePointer;
    expect(ignore.ignoring, isTrue);
  });

  testWidgets('the tap surface covers the whole card', (tester) async {
    await tester.pumpWidget(_host(frameReady: false));
    final positioned = tester.widget<Positioned>(
      find.ancestor(of: find.byType(GestureDetector), matching: find.byType(Positioned)),
    );
    expect(positioned.left, 0);
    expect(positioned.top, 0);
    expect(positioned.right, 0);
    expect(positioned.bottom, 0);
  });
}
