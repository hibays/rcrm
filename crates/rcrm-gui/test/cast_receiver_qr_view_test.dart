// test/cast_receiver_qr_view_test.dart
// CastReceiverQrView (the QR pairing page) layout regression test:
// the page must not overflow on portrait phone sizes in any pairing state.
//
// Regression: the brand header ("Cast Receiver" at 30px) was wider than a
// narrow portrait phone's content column and overflowed the right edge —
// the "black bar" on the right side of the QR page. The header now shrinks
// to fit (FittedBox.scaleDown) and these sizes must stay overflow-free.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/services/cast_protocol.dart';
import 'package:rcrm_gui/widgets/cast_receiver_qr_view.dart';

CastQrPayload _qr() => const CastQrPayload(
  host: '192.168.1.10',
  port: 8901,
  token: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  certSha256:
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
);

void main() {
  // Phone portrait sizes (logical pixels), from small to large.
  const sizes = [
    Size(360, 640),
    Size(390, 844),
    Size(412, 915),
    Size(430, 932),
  ];
  const states = ['usable', 'paired', 'expired'];

  testWidgets('portrait QR page never overflows in any pairing state', (
    tester,
  ) async {
    for (final size in sizes) {
      for (final state in states) {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.reset);

        // Overflowing flex throws RenderFlex overflow errors; the test
        // framework fails on them by default — no manual collection needed,
        // but pump enough frames for layout to settle.
        await tester.pumpWidget(
          MaterialApp(
            home: CastReceiverQrView(
              qr: _qr(),
              paired: state == 'paired',
              usable: state == 'usable',
              badge: state == 'usable'
                  ? null
                  : (state == 'paired' ? 'Paired' : 'Expired'),
              showBack: true,
              localIpv4s: const ['192.168.1.10'],
              pairExpiresAt: DateTime.now().add(const Duration(seconds: 30)),
              serverOk: true,
              tick: true,
              callbacks: const CastReceiverQrViewCallbacks(
                onUnpair: _noop,
                onRegenerate: _noop,
                onSelectIpv4: _noopIp,
              ),
            ),
          ),
        );
        await tester.pump(const Duration(milliseconds: 50));
        await tester.pump(const Duration(milliseconds: 50));

        // The gradient body must cover the FULL screen (the "black bar" /
        // pasted-blocks complaint): with no AppBar the DecoratedBox spans
        // the whole viewport, width and height.
        final bodyBox = tester.getRect(find.byType(DecoratedBox).first);
        expect(
          bodyBox,
          Rect.fromLTWH(0, 0, size.width, size.height),
          reason:
              'QR page background must span the full screen at $size '
              '($state)',
        );

        // The QR card must be horizontally centered (responsive layout,
        // not pushed into a corner) in portrait.
        final qrCard = find.byType(CastReceiverQrCard);
        expect(qrCard, findsOneWidget);
        final qrCenter = tester.getCenter(qrCard);
        expect(
          (qrCenter.dx - size.width / 2).abs(),
          lessThan(1.0),
          reason: 'QR card must be horizontally centered at $size ($state)',
        );

        // The brand header row must fit inside the content column.
        final header = find.text('Cast Receiver');
        expect(header, findsOneWidget);
        final headerBox = tester.getRect(header);
        expect(
          headerBox.right,
          lessThanOrEqualTo(size.width - 12),
          reason:
              'brand header must not overflow the right edge at $size '
              '($state)',
        );

        await tester.pumpWidget(const SizedBox());
      }
    }
  });

  testWidgets('landscape QR page does not overflow', (tester) async {
    tester.view.physicalSize = const Size(844, 390);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      MaterialApp(
        home: CastReceiverQrView(
          qr: _qr(),
          paired: false,
          usable: true,
          badge: null,
          showBack: true,
          localIpv4s: const ['192.168.1.10'],
          pairExpiresAt: DateTime.now().add(const Duration(seconds: 30)),
          serverOk: true,
          tick: true,
          callbacks: const CastReceiverQrViewCallbacks(
            onUnpair: _noop,
            onRegenerate: _noop,
            onSelectIpv4: _noopIp,
          ),
        ),
      ),
    );
    await tester.pump(const Duration(milliseconds: 50));

    final bodyBox = tester.getSize(find.byType(DecoratedBox).first);
    expect(bodyBox.width, 844);
    await tester.pumpWidget(const SizedBox());
  });
}

void _noop() {}
void _noopIp(String _) {}
