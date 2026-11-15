// utils/poster_log.dart
// The poster pipeline's one diagnostic channel.
//
// Poster generation is the pipeline whose cost lives on the device rather than
// in a test, and "the thumbnails are slow" is not reproducible from a bug report
// without the stage numbers (shot / compare / encode / total). Both backends
// therefore report through here, with the same POSTER| prefix and the same probe
// tags, so a phone log and a desktop log read the same.
//
// Debug builds only, and `debugPrint` rather than `print` (per the Dart
// conventions this app follows).

import 'package:flutter/foundation.dart' show kDebugMode, debugPrint;

/// Log one poster diagnostic line. [line] is the part after `POSTER|`.
void posterLog(String line) {
  if (kDebugMode) debugPrint('POSTER|$line');
}
