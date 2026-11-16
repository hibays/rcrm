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
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/finger_preview_listener.dart';
import 'package:rcrm_gui/widgets/player_end_card.dart';
import 'package:rcrm_gui/widgets/video_card.dart';
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
  setUp(() => ThumbnailService.debugPosterLoader = ThumbnailService.noPoster);
  tearDown(() => ThumbnailService.debugPosterLoader = null);

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
    List<MediaItem>? related,
    bool shuffled = false,
    Duration countdown = const Duration(seconds: 3),
    VoidCallback? onAutoPlay,
    VoidCallback? onCancelAutoPlay,
    ValueChanged<MediaItem>? onPick,
  }) => _host(
    PlayerEndCard(
      title: 'current.mp4',
      related: related ?? <MediaItem>[_video('other.mp4')],
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

  testWidgets('tapping the ring tile plays THAT video, not nothing', (
    WidgetTester tester,
  ) async {
    // The dim and the ring are decoration. They used to be a bare
    // `ColoredBox` — which is hit-test OPAQUE — so a tap anywhere in the
    // countdown tile was swallowed by the dim, never reached the tile's own
    // tap handler, and fell through to the picture underneath. On a finished
    // file that picture handler REPLAYS the video the viewer is sitting on.
    MediaItem? picked;
    await tester.pumpWidget(
      offerCard(
        offer: _video('auto.mp4', seconds: 30),
        related: <MediaItem>[_video('auto.mp4', seconds: 30)],
        onPick: (item) => picked = item,
      ),
    );
    await tester.pump(const Duration(milliseconds: 300));

    // The ring tile is the first grid tile; tap its centre, where the ring is.
    final Rect tile = tester.getRect(find.byType(AspectRatio).first);
    await tester.tapAt(tile.center);
    await tester.pump(const Duration(milliseconds: 300));

    expect(picked?.name, 'auto.mp4');
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

  testWidgets('every tile previews on hover except the countdown one', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      offerCard(
        offer: _video('auto.mp4'),
        related: <MediaItem>[_video('a.mp4'), _video('b.mp4')],
      ),
    );
    await tester.pump(const Duration(milliseconds: 250));

    final List<VideoCard> cards = tester
        .widgetList<VideoCard>(find.byType(VideoCard))
        .toList();
    // The offer is hoisted to the first slot, and that is the one tile that
    // must NOT start a second moving picture under its ring.
    expect(cards.first.item.name, 'auto.mp4');
    expect(cards.first.hoverPreview, isFalse);
    expect(
      cards.skip(1).every((VideoCard c) => c.hoverPreview),
      isTrue,
      reason: 'the rest of the grid behaves like every other video list',
    );
  });

  testWidgets('the countdown label counts down with the ring', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      offerCard(
        offer: _video('auto.mp4'),
        countdown: const Duration(seconds: 8),
      ),
    );
    await tester.pump();

    // The label and the ring are the same clock: a label that said "8s" for
    // the whole countdown was a lie from its second second.
    expect(find.text('Auto-plays in 8s'), findsOneWidget);
    await tester.pump(const Duration(seconds: 3));
    expect(find.text('Auto-plays in 5s'), findsOneWidget);
    await tester.pump(const Duration(seconds: 3));
    expect(find.text('Auto-plays in 2s'), findsOneWidget);
  });

  testWidgets('the tiles float on the picture, so they stay dark in Day', (
    WidgetTester tester,
  ) async {
    // The end card's surface is FIXED dark in both appearances (it floats on
    // the picture). Its tiles must be too — a cream tile in a dark card is a
    // light patch on a video.
    RCrmColors.apply(accent: RCrmAccent.marquee, brightness: Brightness.light);
    addTearDown(
      () => RCrmColors.apply(
        accent: RCrmAccent.marquee,
        brightness: Brightness.dark,
      ),
    );

    await tester.pumpWidget(
      offerCard(related: <MediaItem>[_video('a.mp4', seconds: 61)]),
    );
    await tester.pump();

    final Card card = tester.widget<Card>(find.byType(Card).first);
    expect(card.color, RCrmColors.playerSurface);
  });

  testWidgets('the end card and the Related list can both be mounted', (
    WidgetTester tester,
  ) async {
    // The player's Related list and the end card show the SAME files at the
    // same time, and they share one FingerPreviewState. One GlobalKey per
    // path handed both the same key: the framework moved the first card's
    // element into the second's slot and the end card's tiles went BLANK.
    final FingerPreviewState fp = FingerPreviewState();
    final List<MediaItem> related = <MediaItem>[
      _video('a.mp4'),
      _video('b.mp4'),
    ];

    await tester.pumpWidget(
      _host(
        Row(
          children: [
            Expanded(
              child: PlayerEndCard(
                title: 'current.mp4',
                related: related,
                onReplay: () {},
                onPick: (_) {},
                onShowAll: () {},
                onDismiss: () {},
                fingerPreview: fp,
              ),
            ),
            SizedBox(
              width: 200,
              child: ListView(
                children: [
                  for (final MediaItem m in related)
                    SizedBox(
                      height: 90,
                      child: VideoCard(
                        key: fp.surface('related').keyFor(m.path),
                        item: m,
                        compact: true,
                      ),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
    await tester.pump();

    expect(tester.takeException(), isNull);
    // Both surfaces drew their tiles: the end card's grid shows every related
    // item, and the list beside it shows the same ones again.
    expect(find.byType(VideoCard), findsNWidgets(related.length * 2));
  });

  testWidgets('one path on two surfaces is two keys', (
    WidgetTester tester,
  ) async {
    // The rule the blank tiles came from: a GlobalKey belongs to a SURFACE.
    final FingerPreviewState fp = FingerPreviewState();
    final GlobalKey a = fp.surface('one').keyFor('/library/x.mp4');
    final GlobalKey b = fp.surface('two').keyFor('/library/x.mp4');
    expect(identical(a, b), isFalse);
    // ...and the same surface asks for the same key, so the element survives.
    expect(identical(a, fp.surface('one').keyFor('/library/x.mp4')), isTrue);
  });
}
