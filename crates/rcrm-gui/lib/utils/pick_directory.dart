// utils/pick_directory.dart
// The one place that turns a directory picker result into the string the
// server config and the Rust server consume.

import 'package:file_picker/file_picker.dart';
import 'package:flutter/services.dart' show PlatformException;

/// Pick a directory and return the same string `getDirectoryPath()` used to.
///
/// The replacement API returns a [Uri]: desktop wraps the native path in a
/// `file:` URI ([Uri.directory] in the platform interface's default
/// implementation), while Android returns the SAF `content:` URI. Both are
/// converted back to the original string form, so persisted paths and the
/// values handed to Rust keep their existing format.
///
/// A platform error is treated as "nothing chosen" — the deprecated call
/// swallowed it on Android and the picker's cancel path returns null.
Future<String?> pickDirectoryPath() async {
  try {
    return directoryUriToString(await FilePicker.pickDirectory());
  } on PlatformException {
    return null;
  }
}

/// Pure conversion of a picker URI to the stored string. Exposed so the
/// per-platform shapes can be pinned without invoking the native picker.
String? directoryUriToString(Uri? uri) {
  if (uri == null) return null;
  if (uri.scheme != 'file') return uri.toString();
  final path = uri.toFilePath();
  // Uri.directory() adds a trailing separator; the deprecated getDirectoryPath()
  // did not. Keep the stored form stable (duplicate detection compares strings)
  // while leaving roots like `D:\` or `/` intact.
  if (path.length > 3 && (path.endsWith('/') || path.endsWith('\\'))) {
    return path.substring(0, path.length - 1);
  }
  return path;
}
