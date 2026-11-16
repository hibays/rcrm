// test/image_gestures_test.dart
// The photo tab's two new ways in: a two-finger pinch resizing the grid, and a
// long press opening the image's own menu.
//
// The arithmetic is in `utils/library_columns.dart` and the pointer plumbing in
// `widgets/two_finger_pinch.dart`; both are unit-tested. What this file pins is
// the WIRING: the gesture reaches the setting the grid reads, and a long press
// reaches the menu the item offers.

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/image_screen.dart';
import 'package:rcrm_gui/services/media_library.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/widgets/image_card.dart';
import 'package:rcrm_gui/widgets/image_grid.dart';

MediaItem _image(String name) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:18443/$name',
  type: MediaType.image,
  size: 512,
  modified: DateTime(2024, 1, 1),
);

final _images = [_image('a.jpg'), _image('b.png'), _image('c.jpg')];

class _ImageSettings extends SettingsNotifier {
  _ImageSettings(this.columns);
  final int columns;

  @override
  SettingsState build() =>
      SettingsState(imageClassification: 'none', imageColumns: columns);
}

ProviderContainer _container({int columns = 3}) {
  final container = ProviderContainer(
    overrides: [
      uiSettingsProvider.overrideWith(() => _ImageSettings(columns)),
      mediaLibraryProvider.overrideWithValue(
        MediaLibrary(WebDavClient(baseUrl: 'http://127.0.0.1:18443')),
      ),
    ],
  );
  addTearDown(container.dispose);
  container.read(imagesMapProvider.notifier).addAll(_images);
  return container;
}

Future<void> _pump(WidgetTester tester, ProviderContainer c) async {
  tester.view.physicalSize = const Size(800, 800);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: const Scaffold(body: ImageScreen()),
      ),
    ),
  );
  await tester.pump();
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('a two-finger pinch changes the photo grid columns', (
    tester,
  ) async {
    final c = _container(columns: 3);
    await _pump(tester, c);

    expect(tester.widget<ImageGrid>(find.byType(ImageGrid)).crossAxisCount, 3);

    // Two fingers 100dp apart, spread to 200dp: scale 2, so 3 columns -> 2.
    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    await a.down(const Offset(300, 400));
    await b.down(const Offset(400, 400));
    await tester.pump();
    await a.moveTo(const Offset(250, 400));
    await b.moveTo(const Offset(450, 400));
    await tester.pump();
    await a.up();
    await b.up();
    await tester.pumpAndSettle();

    expect(c.read(uiSettingsProvider).imageColumns, 2);
    expect(
      tester.widget<ImageGrid>(find.byType(ImageGrid)).crossAxisCount,
      2,
      reason: 'the setting the gesture wrote is the one the grid reads',
    );
  });

  testWidgets('a long press opens the image menu where the finger was', (
    tester,
  ) async {
    await _pump(tester, _container());

    await tester.longPress(find.byType(ImageCard).first);
    await tester.pumpAndSettle();

    expect(find.text('Open'), findsOneWidget);
    expect(find.text('Details'), findsOneWidget);
    expect(find.text('Copy name'), findsOneWidget);
    expect(find.text('Copy path'), findsOneWidget);
    expect(
      find.text('Show in folder'),
      findsNothing,
      reason: 'the photo tab has no free folder view to reveal into',
    );

    // Dismiss without choosing, so the test ends with no open surface.
    await tester.tapAt(const Offset(20, 700));
    await tester.pumpAndSettle();
    expect(find.text('Open'), findsNothing);
  });
}
