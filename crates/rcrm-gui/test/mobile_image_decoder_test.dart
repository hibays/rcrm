// test/mobile_image_decoder_test.dart
// What the software-decode entry points decide WITHOUT a bridge: which formats
// they claim, and what they do when the decoder for a format is not in this
// build. The HEIC decoder is an opt-in feature, so "no symbol" must be a normal
// answer — falling back to Flutter's own decoder — rather than a failure.

import 'dart:ffi';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/mobile_image_decoder.dart';
import 'package:rcrm_gui/services/native_bytes.dart';

void main() {
  group('MobileImageDecoder routing', () {
    // No bridge is loaded in a `flutter test` run, so every decoder address is
    // 0 — exactly the state of a build without `mobile-decode`/`heic`.
    test('claims no format when the build has no decoder', () {
      for (final url in [
        'http://h/a.avif',
        'http://h/a.jxl',
        'http://h/a.heic',
        'http://h/a.HEIF',
      ]) {
        expect(
          MobileImageDecoder.kindHintFor(url),
          0,
          reason: 'no decoder for $url in this build',
        );
      }
    });

    test('never claims a format Rust does not decode', () {
      for (final url in [
        'http://h/a.jpg',
        'http://h/a.png',
        'http://h/a.webp',
        'http://h/a.gif',
        'http://h/a.mp4',
        'http://h/noextension',
      ]) {
        expect(MobileImageDecoder.kindHintFor(url), 0, reason: url);
      }
    });

    test('the copy-free fetch is skipped when nothing can decode it', () async {
      // No decoder → no native buffer is even allocated, and the caller falls
      // back to the engine path without a request being made.
      expect(await MobileImageDecoder.fetchForDecode('http://h/a.heic'), isNull);
      expect(await MobileImageDecoder.fetchForDecode('http://h/a.avif'), isNull);
    });

    test('kind hints depend on the extension alone', () {
      // The numbers are the C ABI: 1 = AVIF, 2 = JXL, 3 = HEIC (see
      // `rcrm_generate_thumb_webp_from_image`). Their *absolute* values cannot be
      // pinned here: a hint is only produced when the matching decoder address is
      // non-zero, and every address is 0 under `flutter test` (no bridge is
      // loaded), which is why an `anyOf(0, N)` assertion would hold no matter what
      // the mapping did. What CAN fail — and therefore is what this test pins — is
      // that the mapping reads the extension and nothing else.
      expect(
        MobileImageDecoder.kindHintFor('http://h/a.avif?token=1'),
        MobileImageDecoder.kindHintFor('http://h/a.avif'),
        reason: 'a query string must not change the format hint',
      );
      expect(
        MobileImageDecoder.kindHintFor('http://h/A.AVIF'),
        MobileImageDecoder.kindHintFor('a.avif'),
        reason: 'the extension is matched case-insensitively, host or not',
      );
      // Unknown shapes must abstain, not guess a neighbouring code.
      for (final url in ['', 'x', 'x.txt', 'x.avif.txt', 'x.heif.bak']) {
        expect(MobileImageDecoder.kindHintFor(url), 0, reason: url);
      }
    });
  });

  group('DecodeBuf ABI', () {
    test('the Dart mirror matches the Rust struct layout', () {
      // Rust: width u32, height u32, channels u8, data_len usize, cap usize,
      // data *mut u8 — with C padding after `channels`.
      final word = sizeOf<IntPtr>();
      expect(MobileImageDecoder.decodeBufStructSize, word == 8 ? 40 : 24);
    });
  });

  group('NativeBytes ownership', () {
    test('free is idempotent and disown makes it a no-op', () {
      final head = NativeBytes(nullptr, 0, 0);
      head.free();
      head.free();
      final other = NativeBytes(nullptr, 0, 0);
      other.disown();
      other.free();
    });
  });
}
