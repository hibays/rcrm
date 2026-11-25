// test/pick_directory_test.dart
// The picker returns a Uri on the new API; the server config still stores a
// String. Pin the conversion for each platform shape.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/pick_directory.dart';

void main() {
  group('directoryUriToString', () {
    test('null stays null (cancelled picker)', () {
      expect(directoryUriToString(null), isNull);
    });

    test('a file URI becomes the filesystem path', () {
      final uri = Uri.directory(
        Platform.isWindows ? r'C:\Media' : '/srv/media',
        windows: Platform.isWindows,
      );
      final path = directoryUriToString(uri);
      expect(path, isNotNull);
      expect(path, contains(Platform.isWindows ? 'Media' : 'media'));
      expect(path, isNot(contains('file:')));
      // Matches the deprecated API's form: no trailing separator.
      expect(path, isNot(endsWith(Platform.isWindows ? '\\' : '/')));
    });

    test('an Android SAF content URI is kept as the native string', () {
      const raw =
          'content://com.android.externalstorage.documents/tree/'
          'primary%3ADCIM';
      expect(directoryUriToString(Uri.parse(raw)), raw);
    });
  });
}
