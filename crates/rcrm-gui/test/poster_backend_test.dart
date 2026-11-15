// test/poster_backend_test.dart
// Which poster backend a build uses, pinned as the two facts that decide it.
//
// The pipeline used to be split by platform ("desktop" ran ffmpeg, "mobile" ran
// media_kit); it is now split by what can render a frame at all. These three
// cases are the whole rule, including the one that keeps an older bridge (or a
// build that omitted `libmpv-poster`) working.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/poster_backend.dart';

void main() {
  group('choosePosterBackend', () {
    test('iOS always takes the media_kit screenshot', () {
      // Its libmpv is linked into the app: no shared library exists to load,
      // and the platform refuses an arbitrary dlopen.
      expect(
        choosePosterBackend(isIOS: true, hasLibMpv: true),
        PosterBackend.mpv,
      );
      expect(
        choosePosterBackend(isIOS: true, hasLibMpv: false),
        PosterBackend.mpv,
      );
    });

    test('every other platform renders with libmpv when the export exists', () {
      expect(
        choosePosterBackend(isIOS: false, hasLibMpv: true),
        PosterBackend.libmpv,
      );
    });

    test('a bridge without the export falls back to media_kit', () {
      // An older build (or one built without the feature) has no direct-render
      // export; media_kit can still take a screenshot, which is why this is a
      // fallback rather than an error.
      expect(
        choosePosterBackend(isIOS: false, hasLibMpv: false),
        PosterBackend.mpv,
      );
    });
  });
}
