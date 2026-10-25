// test/player_error_text_test.dart
// The two pure pieces of the player's error path: the ffmpeg HTTP log
// classifier (media_kit drops those from stream.error) and the bounded text
// shown in the overlay.

import 'package:flutter_test/flutter_test.dart';
import 'package:media_kit/media_kit.dart';
import 'package:rcrm_gui/utils/player_error_text.dart';

void main() {
  group('isFatalHttpLog', () {
    test('an ffmpeg HTTP error is the one stream.error drops', () {
      expect(
        isFatalHttpLog(
          const PlayerLog(
            prefix: 'ffmpeg',
            level: 'error',
            text: 'http: HTTP error 404 Not Found',
          ),
        ),
        isTrue,
      );
    });

    test('other prefixes, levels and protocols are not fatal', () {
      expect(
        isFatalHttpLog(
          const PlayerLog(prefix: 'cplayer', level: 'error', text: 'http: 404'),
        ),
        isFalse,
      );
      expect(
        isFatalHttpLog(
          const PlayerLog(prefix: 'ffmpeg', level: 'warn', text: 'http: 404'),
        ),
        isFalse,
      );
      expect(
        isFatalHttpLog(
          const PlayerLog(prefix: 'ffmpeg', level: 'error', text: 'tcp: reset'),
        ),
        isFalse,
      );
    });
  });

  group('describePlaybackError', () {
    test('collapses whitespace and bounds the line', () {
      final text = describePlaybackError('Failed\nto   open\tthis video');
      expect(text, 'Failed to open this video');
    });

    test('an empty error still says something', () {
      expect(
        describePlaybackError(''),
        'The player could not open this video.',
      );
    });

    test('a long error is shortened', () {
      final text = describePlaybackError('x' * 400);
      expect(text.length, 180);
      expect(text.endsWith('...'), isTrue);
    });
  });
}
