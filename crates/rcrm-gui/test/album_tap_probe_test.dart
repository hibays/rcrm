import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/album.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/widgets/album_card.dart';

void main() {
  testWidgets('AlbumCard onTap fires on tap', (tester) async {
    var taps = 0;
    final album = Album.fromItems(
      name: 'Japan',
      path: '/Japan',
      url: 'http://127.0.0.1:8080/Japan',
      items: [
        MediaItem(
          name: 'tokyo.jpg',
          path: '/Japan/tokyo.jpg',
          url: 'http://127.0.0.1:8080/Japan/tokyo.jpg',
          type: MediaType.image,
          size: 100,
        ),
      ],
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Center(
            child: SizedBox(
              width: 200,
              height: 250,
              child: AlbumCard(album: album, onTap: () => taps++),
            ),
          ),
        ),
      ),
    );
    await tester.pump();
    await tester.tap(find.byType(AlbumCard));
    await tester.pump();
    debugPrint('taps=$taps');
    expect(taps, 1);
  });
}
