// test/player_end_card_test.dart
// The end card's contract: which actions exist, what a missing Related list
// does, how many tiles the grid admits, and that closing always reports back
// exactly once — the screen unmounts only after the exit has played.
//
// Posters are suppressed (ThumbnailService's own test hook): this widget is
// about the decision surface, not about generating a frame, and a poster that
// is never asked for keeps the test off the network.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/player_end_card.dart';
import 'package:rcrm_gui/widgets/video_poster.dart';

MediaItem _video(String name, {int? seconds}) => MediaItem(
  name: name,
  path: '/library/$name',
  url: 'http://127.0.0.1:9/$name',
  type: MediaType.video,
  durationSeconds: seconds,
);

Widget _host(Widget child, {bool? disableAnimations}) => MaterialApp(
  home: Builder(
    builder: (BuildContext context) {
      // Copy the enclosing MediaQuery instead of replacing it: a bare
      // MediaQueryData() has Size.zero, which starves the card of height and
      // makes every assertion below a lie about the real layout.
      final MediaQueryData base = MediaQuery.of(context);
      return MediaQuery(
        data: disableAnimations == null
            ? base
            : base.copyWith(disableAnimations: disableAnimations),
        child: Scaffold(
          backgroundColor: const Color(0xFF0E0E0E),
          body: child,
        ),
      );
    },
  ),
);

void main() {
  setUp(() => ThumbnailService.suppressPosterGeneration = true);
  tearDown(() => ThumbnailService.suppressPosterGeneration = false);

  testWidgets('offers replay, the next video and the whole list', (
    WidgetTester tester,
  ) async {
    final List<MediaItem> related = <MediaItem>[
      _video('next.mp4', seconds: 61),
      _video('other.mp4'),
    ];
    int replay = 0;
    MediaItem? picked;
    int showAll = 0;

    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'current.mp4',
          related: related,
          onReplay: () => replay++,
          onPick: (MediaItem item) => picked = item,
          onShowAll: () => showAll++,
          onDismiss: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Playback finished'), findsOneWidget);
    expect(find.text('current.mp4'), findsOneWidget);
    expect(find.text('Replay'), findsOneWidget);
    expect(find.text('All 2'), findsOneWidget);
    // The first tile IS "play next"; a separate button would be a second door.
    expect(find.text('Play next'), findsNothing);
    expect(find.text('01:01'), findsOneWidget);

    await tester.tap(find.text('Replay'));
    expect(replay, 1);

    await tester.tap(find.text('next.mp4'));
    expect(picked?.name, 'next.mp4');

    await tester.tap(find.text('All 2'));
    expect(showAll, 1);
  });

  testWidgets('an empty Related list still leaves a way out', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'lonely.mp4',
          related: const <MediaItem>[],
          onReplay: () {},
          onPick: (_) {},
          onShowAll: () {},
          onDismiss: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('No related videos'), findsOneWidget);
    expect(find.text('Replay'), findsOneWidget);
    expect(find.text('Play next'), findsNothing);
    expect(find.text('All 0'), findsNothing);
    expect(find.byType(VideoPoster), findsNothing);
  });

  testWidgets('where the episode sheet does not exist, its button is absent', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'windowed.mp4',
          related: <MediaItem>[_video('next.mp4')],
          onReplay: () {},
          onPick: (_) {},
          onShowAll: null,
          onDismiss: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    // The tile is still the way to play the next video; the SHEET is what is
    // missing, so its button is absent.
    expect(find.text('next.mp4'), findsOneWidget);
    expect(find.textContaining('All '), findsNothing);
  });

  testWidgets('the grid admits two rows of three, and no more', (
    WidgetTester tester,
  ) async {
    final List<MediaItem> many = List<MediaItem>.generate(
      10,
      (int i) => _video('v$i.mp4'),
    );
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'many.mp4',
          related: many,
          onReplay: () {},
          onPick: (_) {},
          onShowAll: () {},
          onDismiss: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    // The test surface is 800dp wide: the card caps at 720, which is the
    // three-column tier, so the visible cap is 3 × 2.
    expect(find.byType(VideoPoster), findsNWidgets(6));
  });

  testWidgets('tapping a tile picks that video', (WidgetTester tester) async {
    MediaItem? picked;
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'current.mp4',
          related: <MediaItem>[_video('tile.mp4')],
          onReplay: () {},
          onPick: (MediaItem item) => picked = item,
          onShowAll: () {},
          onDismiss: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('tile.mp4'));
    expect(picked?.name, 'tile.mp4');
  });

  testWidgets('closing reports back once, after the exit', (
    WidgetTester tester,
  ) async {
    int dismissed = 0;
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'current.mp4',
          related: <MediaItem>[_video('next.mp4')],
          onReplay: () {},
          onPick: (_) {},
          onShowAll: () {},
          onDismiss: () => dismissed++,
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.byIcon(Icons.close));
    await tester.pumpAndSettle();
    expect(dismissed, 1);
  });

  testWidgets('the backdrop is a second door to the same refusal', (
    WidgetTester tester,
  ) async {
    int dismissed = 0;
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'current.mp4',
          related: <MediaItem>[_video('next.mp4')],
          onReplay: () {},
          onPick: (_) {},
          onShowAll: () {},
          onDismiss: () => dismissed++,
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tapAt(const Offset(4, 4));
    await tester.pumpAndSettle();
    expect(dismissed, 1);
  });

  testWidgets('reduced motion closes without waiting for the exit', (
    WidgetTester tester,
  ) async {
    int dismissed = 0;
    await tester.pumpWidget(
      _host(
        PlayerEndCard(
          title: 'current.mp4',
          related: <MediaItem>[_video('next.mp4')],
          onReplay: () {},
          onPick: (_) {},
          onShowAll: () {},
          onDismiss: () => dismissed++,
        ),
        disableAnimations: true,
      ),
    );
    await tester.pump();

    await tester.tap(find.byIcon(Icons.close));
    await tester.pump();
    expect(dismissed, 1);
  });

  Widget offerCard({
    MediaItem? offer,
    bool shuffled = false,
    Duration countdown = const Duration(seconds: 3),
    VoidCallback? onAutoPlay,
    VoidCallback? onCancelAutoPlay,
    ValueChanged<MediaItem>? onPick,
  }) => _host(
    PlayerEndCard(
      title: 'current.mp4',
      related: <MediaItem>[_video('other.mp4')],
      autoPlayItem: offer,
      autoPlayShuffled: shuffled,
      countdown: countdown,
      onAutoPlay: onAutoPlay,
      onCancelAutoPlay: onCancelAutoPlay,
      onReplay: () {},
      onPick: onPick ?? (_) {},
      onShowAll: () {},
      onDismiss: () {},
    ),
  );

  testWidgets('the offer becomes the first tile, ringed and cancellable', (
    WidgetTester tester,
  ) async {
    var cancelled = 0;
    await tester.pumpWidget(
      offerCard(
        offer: _video('auto.mp4', seconds: 30),
        shuffled: true,
        onCancelAutoPlay: () => cancelled++,
      ),
    );
    await tester.pump(const Duration(milliseconds: 250));

    // Shuffle says where the pick came from; the ring is on the video it will
    // play, which is the FIRST tile however the list was ordered.
    expect(find.text('Random pick · auto-plays in 3s'), findsOneWidget);
    expect(find.text('Cancel'), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    final List<VideoPoster> posters = tester
        .widgetList<VideoPoster>(find.byType(VideoPoster))
        .toList();
    expect(posters.first.item.name, 'auto.mp4');

    await tester.tap(find.text('Cancel'));
    expect(cancelled, 1);
  });

  testWidgets('the countdown advances once, not on every frame after', (
    WidgetTester tester,
  ) async {
    var auto = 0;
    await tester.pumpWidget(
      offerCard(offer: _video('auto.mp4'), onAutoPlay: () => auto++),
    );
    await tester.pump(const Duration(seconds: 1));
    expect(auto, 0, reason: 'not before the countdown');

    await tester.pumpAndSettle();
    expect(auto, 1);

    await tester.pump(const Duration(seconds: 2));
    expect(auto, 1);
  });

  testWidgets('withdrawing the offer stops the clock and the ring', (
    WidgetTester tester,
  ) async {
    var auto = 0;
    await tester.pumpWidget(
      offerCard(offer: _video('auto.mp4'), onAutoPlay: () => auto++),
    );
    await tester.pump(const Duration(seconds: 1));

    // This is what `Cancel` does at the screen: the offer goes, the card and
    // its Related grid stay.
    await tester.pumpWidget(
      offerCard(offer: null, onAutoPlay: () => auto++),
    );
    await tester.pump(const Duration(seconds: 3));

    expect(auto, 0);
    expect(find.text('Cancel'), findsNothing);
    expect(find.byType(CircularProgressIndicator), findsNothing);
  });
}
