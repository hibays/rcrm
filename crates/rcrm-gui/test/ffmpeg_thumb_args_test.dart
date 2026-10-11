// test/ffmpeg_thumb_args_test.dart
// The desktop VIDEO THUMBNAIL poster's ffmpeg command line, pinned as an ORDER.
//
// `-hide_banner` and `-tls_verify 0` only do what they say in the right
// position: `-hide_banner` is global (before any input), and `-tls_verify` is an
// input option of the `tls` protocol — written after `-i <url>` ffmpeg ignores
// it, and the fetch then fails exactly as it did before the fix, because
// ffmpeg ≥ 9 verifies TLS peers by default (`tls_verify=1`) while RCrm's HTTPS
// server presents a self-signed certificate.
//
// Position is not the only way to get this wrong. ffmpeg resolves the *name* of
// an input option against the protocol the URL selects, after choosing it, and
// aborts the whole command when that protocol does not define the name:
//
//   file:     + flag  → "Option tls_verify not found."  exit ≠ 0, no output
//   http://   + flag  → "Option tls_verify not found."  exit ≠ 0, no output
//   http://   no flag → exit 0, JPEG
//   https://  + flag  → exit 0, JPEG
//   https://  no flag → exit -5, "Peer certificate failed verification"
//
// So the flag is conditional on the scheme, and both directions are pinned here:
// the desktop app's own server is plain `http://127.0.0.1:<port>`, where the
// flag would leave every poster empty.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/ffmpeg_thumb_args.dart';

void main() {
  group('ffmpegThumbArgs', () {
    test('the full list, https, input-seek mode', () {
      expect(
        ffmpegThumbArgs(
          url: 'https://127.0.0.1:8443/v/a%20b.mp4',
          headers: {'Authorization': 'Basic dTpw'},
          seekSeconds: 30.0,
          frames: 1,
          width: 640,
          inputSeek: true,
        ),
        [
          '-hide_banner',
          '-tls_verify',
          '0',
          '-headers',
          'Authorization: Basic dTpw',
          '-ss',
          '30.0',
          '-an',
          '-i',
          'https://127.0.0.1:8443/v/a%20b.mp4',
          '-vframes',
          '1',
          '-q:v',
          '3',
          '-vf',
          'scale=640:-1',
          '-f',
          'image2',
          '-c:v',
          'mjpeg',
          'pipe:1',
        ],
      );
    });

    test(
      'the full list, plain http: the TLS flag is gone, nothing else moves',
      () {
        // The same call as above with one character of scheme changed. This is the
        // desktop app's own loopback server (`http://127.0.0.1:<port>`).
        expect(
          ffmpegThumbArgs(
            url: 'http://127.0.0.1:8080/v/a%20b.mp4',
            headers: {'Authorization': 'Basic dTpw'},
            seekSeconds: 30.0,
            frames: 1,
            width: 640,
            inputSeek: true,
          ),
          [
            '-hide_banner',
            '-headers',
            'Authorization: Basic dTpw',
            '-ss',
            '30.0',
            '-an',
            '-i',
            'http://127.0.0.1:8080/v/a%20b.mp4',
            '-vframes',
            '1',
            '-q:v',
            '3',
            '-vf',
            'scale=640:-1',
            '-f',
            'image2',
            '-c:v',
            'mjpeg',
            'pipe:1',
          ],
        );
      },
    );

    test('the scheme alone decides the flag, in both seek modes', () {
      List<String> argsFor(String url, {required bool inputSeek}) =>
          ffmpegThumbArgs(
            url: url,
            headers: const {},
            seekSeconds: 5,
            frames: 1,
            width: 640,
            inputSeek: inputSeek,
          );

      for (final inputSeek in [true, false]) {
        // https, including an uppercase scheme (Uri lower-cases it).
        expect(
          argsFor('https://h/v.mp4', inputSeek: inputSeek),
          contains('-tls_verify'),
          reason: 'inputSeek=$inputSeek',
        );
        expect(
          argsFor('HTTPS://h/v.mp4', inputSeek: inputSeek),
          contains('-tls_verify'),
          reason: 'inputSeek=$inputSeek',
        );
        // Everything else: the flag is not in those protocols' option tables, and
        // ffmpeg turns an unknown input option into a fatal error.
        for (final url in [
          'http://h/v.mp4',
          'http://127.0.0.1:8080/v.mp4',
          'file:///c:/v.mp4',
          'v.mp4',
          'not a url',
        ]) {
          expect(
            argsFor(url, inputSeek: inputSeek),
            isNot(contains('-tls_verify')),
            reason: '$url (inputSeek=$inputSeek)',
          );
        }
      }
    });

    test('the full list, output-seek mode: only -ss moves', () {
      final input = ffmpegThumbArgs(
        url: 'https://h/v.mp4',
        headers: {'Authorization': 'Basic dTpw'},
        seekSeconds: 0.5,
        frames: 1,
        width: 640,
        inputSeek: true,
      );
      final output = ffmpegThumbArgs(
        url: 'https://h/v.mp4',
        headers: {'Authorization': 'Basic dTpw'},
        seekSeconds: 0.5,
        frames: 1,
        width: 640,
        inputSeek: false,
      );
      // `-ss` as an output option lands after `-i` (accurate but slow), and the
      // two lists are otherwise identical — compare the seek itself and the
      // lists with `-ss 0.5` taken out.
      expect(input.sublist(0, 6), [
        '-hide_banner',
        '-tls_verify',
        '0',
        '-headers',
        'Authorization: Basic dTpw',
        '-ss',
      ]);
      expect(input[6], '0.5');
      expect(output[output.indexOf('-i') + 1], 'https://h/v.mp4');
      expect(output.sublist(output.indexOf('-i') + 2), [
        '-ss',
        '0.5',
        '-vframes',
        '1',
        '-q:v',
        '3',
        '-vf',
        'scale=640:-1',
        '-f',
        'image2',
        '-c:v',
        'mjpeg',
        'pipe:1',
      ], reason: 'the tail after -i must not be reordered by the seek mode');
      List<String> withoutSeek(List<String> a) {
        final b = [...a];
        b.removeRange(b.indexOf('-ss'), b.indexOf('-ss') + 2);
        return b;
      }

      expect(withoutSeek(input), withoutSeek(output));
    });

    test('-hide_banner is first: it is a global option', () {
      for (final url in ['https://h/v.mp4', 'http://h/v.mp4']) {
        final args = ffmpegThumbArgs(
          url: url,
          headers: {'Authorization': 'Basic dTpw'},
          seekSeconds: 0,
          frames: 1,
          width: 640,
          inputSeek: true,
        );
        expect(args.first, '-hide_banner', reason: url);
        expect(
          args.indexOf('-hide_banner'),
          lessThan(args.indexOf('-i')),
          reason: url,
        );
      }
    });

    test('for https, -tls_verify 0 appears before the -i it applies to', () {
      for (final inputSeek in [true, false]) {
        final args = ffmpegThumbArgs(
          url: 'https://h/v.mp4',
          headers: {'Authorization': 'Basic dTpw'},
          seekSeconds: 0,
          frames: 1,
          width: 640,
          inputSeek: inputSeek,
        );
        final i = args.indexOf('-i');
        final v = args.indexOf('-tls_verify');
        expect(v, isNonNegative, reason: 'inputSeek=$inputSeek');
        expect(
          v,
          lessThan(i),
          reason:
              'an input option after -i is silently ignored (inputSeek=$inputSeek)',
        );
        expect(args[v + 1], '0');
        // It relaxes exactly one fetch path and nothing else: the URL it applies
        // to is the one right after -i.
        expect(args[i + 1], 'https://h/v.mp4');
      }
    });

    test('the Authorization header and output options are unchanged', () {
      final args = ffmpegThumbArgs(
        url: 'https://h/v.mp4',
        headers: {'Authorization': 'Basic dTpw'},
        seekSeconds: 0,
        frames: 1,
        width: 640,
        inputSeek: true,
      );
      // One argv element, so no shell is involved and the value reaches ffmpeg
      // as written — the header still carries the credentials (never the URL).
      expect(args, contains('Authorization: Basic dTpw'));
      expect(args.where((a) => a.contains('dTpw')), hasLength(1));
      expect(args.sublist(args.indexOf('-vframes')), [
        '-vframes',
        '1',
        '-q:v',
        '3',
        '-vf',
        'scale=640:-1',
        '-f',
        'image2',
        '-c:v',
        'mjpeg',
        'pipe:1',
      ]);
      // stdout, not a file: the zero-disk-writes rule.
      expect(args.last, 'pipe:1');
    });

    test('multiple headers are CRLF-joined into one argv element', () {
      final args = ffmpegThumbArgs(
        url: 'https://h/v.mp4',
        headers: {'Authorization': 'Basic dTpw', 'X-Test': '1'},
        seekSeconds: 0,
        frames: 1,
        width: 640,
        inputSeek: true,
      );
      expect(
        args[args.indexOf('-headers') + 1],
        'Authorization: Basic dTpw\r\nX-Test: 1',
      );
    });

    test('width and frames come from the arguments', () {
      final args = ffmpegThumbArgs(
        url: 'https://h/v.mp4',
        headers: const {},
        seekSeconds: 3,
        frames: 2,
        width: 320,
        inputSeek: true,
      );
      expect(args[args.indexOf('-vf') + 1], 'scale=320:-1');
      expect(args[args.indexOf('-vframes') + 1], '2');
      // No headers → no -headers element at all.
      expect(args.contains('-headers'), isFalse);
      // A whole number keeps Dart's double rendering, which is what the service
      // passes: the position list is `List<double>`.
      expect(args[args.indexOf('-ss') + 1], '3.0');
    });
  });
}
