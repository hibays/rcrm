// test/doctor_sample_test.dart
// The health panel's sample check reads a HEAD of one file, and says so.
//
// The check exists to prove the decrypt → serve → fetch path works end to end,
// which the first chunk of an encrypted file already does. It used to read the
// whole file (`getFile`, one whole video through the decrypting server and into
// Dart memory) and print its length — a stall in the panel that is supposed to
// diagnose stalls. Both halves of the fix are pinned here: the request is
// bounded, and the label reports what was READ rather than what the file is.

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/server_provider.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/widgets/doctor_panel.dart';

const int _fileBytes = 1024 * 1024 * 1024; // 1 GiB of "video"

class _HeadOnlyWebDav extends WebDavClient {
  _HeadOnlyWebDav() : super(baseUrl: 'http://127.0.0.1:1');

  int? askedFor;

  @override
  Future<bool> ping() async => true;

  @override
  Future<List<String>> listSubdirectories(String path) async => const [];

  @override
  Future<List<MediaItem>> listDirectory(String path) async => [
    MediaItem(
      name: 'big.mp4',
      path: '/big.mp4',
      url: 'http://127.0.0.1:1/big.mp4',
      type: MediaType.video,
      size: _fileBytes,
      modified: DateTime(2024, 1, 1),
    ),
  ];

  @override
  Future<Uint8List?> getFileHead(String path, {required int maxBytes}) async {
    askedFor = maxBytes;
    return Uint8List(maxBytes);
  }
}

void main() {
  Future<ProviderContainer> pumpPanel(WidgetTester tester) async {
    await tester.binding.setSurfaceSize(const Size(900, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));

    final fake = _HeadOnlyWebDav();
    final c = ProviderContainer();
    addTearDown(c.dispose);
    c.read(serverProvider.notifier).state = ServerState(
      status: ServerStatus.running,
      url: 'http://127.0.0.1:1',
      client: fake,
    );

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: c,
        child: const MaterialApp(
          home: Scaffold(body: SingleChildScrollView(child: DoctorPanel())),
        ),
      ),
    );
    await tester.pump();
    return c;
  }

  testWidgets('the sample check asks for a head, never the file', (
    tester,
  ) async {
    await pumpPanel(tester);

    await tester.tap(find.text('Library Health Check'));
    await tester.pump();
    await tester.pump();

    expect(find.text('All checks passed'), findsOneWidget);
    expect(
      _fakeFrom(tester)?.askedFor,
      kDoctorSampleBytes,
      reason: 'the bound is the panel\'s own policy and must reach the client',
    );
  });

  testWidgets('the detail reports the head that was read, not the file size', (
    tester,
  ) async {
    await pumpPanel(tester);

    await tester.tap(find.text('Library Health Check'));
    await tester.pump();
    await tester.pump();
    await tester.tap(find.byTooltip('Run check'));
    await tester.pump();
    await tester.pump();
    // Expand the details.
    await tester.tap(find.byIcon(Icons.expand_more));
    await tester.pump();

    expect(
      find.textContaining('first $kDoctorSampleBytes bytes decrypted'),
      findsOneWidget,
    );
    expect(
      find.textContaining('$_fileBytes'),
      findsNothing,
      reason: 'a 1 GiB file must not be reported as if it had been read',
    );
  });
}

/// The fake the panel is talking to — reached through the provider container
/// rather than through the widget tree, because that is where it was installed.
_HeadOnlyWebDav? _fakeFrom(WidgetTester tester) {
  final scope = tester.widget<UncontrolledProviderScope>(
    find.byType(UncontrolledProviderScope),
  );
  return scope.container.read(serverProvider).client as _HeadOnlyWebDav?;
}
