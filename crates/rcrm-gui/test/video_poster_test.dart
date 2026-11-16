// test/video_poster_test.dart
// The poster tile must never become a spinner that never stops: the spinner has a
// budget (`kPosterSpinnerBudget`), the job is not cancelled, and a late poster
// still replaces the placeholder. `debugPosterLoader` is the seam.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/video_poster.dart';

// A short name on purpose: the test VM draws with the Ahem font, whose metrics
// are not Roboto's.
MediaItem _video() => const MediaItem(
  name: 'N.mkv',
  path: '/movies/night.mkv',
  url: 'http://127.0.0.1:8080/movies/night.mkv',
  type: MediaType.video,
  size: 1024 * 1024 * 700,
  durationSeconds: 780,
);

/// A real 1x1 PNG, so the late answer below paints an Image instead of failing
/// to decode and falling through to the error builder.
final Uint8List _png = base64Decode(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
);

const ValueKey<String> kLoadingKey = ValueKey<String>('loading');
const ValueKey<String> kFallbackKey = ValueKey<String>('fallback');

Widget _host(VideoPoster poster) => MaterialApp(
  home: Scaffold(
    body: Center(child: SizedBox(width: 200, height: 120, child: poster)),
  ),
);

void main() {
  tearDown(() => ThumbnailService.debugPosterLoader = null);

  testWidgets('the spinner gives way to the placeholder at the budget', (
    WidgetTester tester,
  ) async {
    final pending = Completer<Uint8List?>();
    ThumbnailService.debugPosterLoader = (_) => pending.future;

    await tester.pumpWidget(
      _host(
        VideoPoster(
          item: _video(),
          loading: const ColoredBox(key: kLoadingKey, color: Colors.black),
          fallback: const ColoredBox(key: kFallbackKey, color: Colors.black),
        ),
      ),
    );
    await tester.pump();
    expect(
      find.byKey(kLoadingKey),
      findsOneWidget,
      reason: 'the poster is pending',
    );
    expect(find.byKey(kFallbackKey), findsNothing);

    // One second short of the budget: still waiting, and still spinning.
    await tester.pump(kPosterSpinnerBudget - const Duration(seconds: 1));
    expect(find.byKey(kLoadingKey), findsOneWidget);
    expect(find.byKey(kFallbackKey), findsNothing);

    await tester.pump(const Duration(seconds: 2));
    expect(
      find.byKey(kLoadingKey),
      findsNothing,
      reason: 'the spinner is bounded',
    );
    expect(find.byKey(kFallbackKey), findsOneWidget);

    // The job is still out there. Its answer may arrive late; it must not throw
    // and must not resurrect the spinner.
    pending.complete(null);
    await tester.pump();
    expect(find.byKey(kFallbackKey), findsOneWidget);
    expect(find.byKey(kLoadingKey), findsNothing);
  });

  testWidgets('a late poster still replaces the placeholder', (
    WidgetTester tester,
  ) async {
    final pending = Completer<Uint8List?>();
    ThumbnailService.debugPosterLoader = (_) => pending.future;

    await tester.pumpWidget(
      _host(
        VideoPoster(
          item: _video(),
          loading: const ColoredBox(key: kLoadingKey, color: Colors.black),
          fallback: const ColoredBox(key: kFallbackKey, color: Colors.black),
        ),
      ),
    );
    await tester.pump();
    await tester.pump(kPosterSpinnerBudget + const Duration(seconds: 1));
    expect(find.byKey(kFallbackKey), findsOneWidget);

    pending.complete(_png);
    // Two turns: the first flushes the answer through `_load`, the second builds
    // the frame it marked dirty.
    await tester.pump();
    await tester.pump();
    expect(
      find.byType(Image),
      findsOneWidget,
      reason: 'a slow poster is painted when it arrives, not thrown away',
    );
  });

  testWidgets('a null answer is the placeholder at once, not a spinner', (
    WidgetTester tester,
  ) async {
    ThumbnailService.debugPosterLoader = (_) async => null;

    await tester.pumpWidget(
      _host(
        VideoPoster(
          item: _video(),
          loading: const ColoredBox(key: kLoadingKey, color: Colors.black),
          fallback: const ColoredBox(key: kFallbackKey, color: Colors.black),
        ),
      ),
    );
    await tester.pump();
    await tester.pump();

    // No budget wait on this path: "no poster for this file" is an answer, not
    // a delay (the queue being slow is the only thing that waits).
    expect(find.byKey(kFallbackKey), findsOneWidget);
    expect(find.byKey(kLoadingKey), findsNothing);
  });
}
