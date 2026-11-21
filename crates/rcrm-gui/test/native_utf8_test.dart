// test/native_utf8_test.dart
// The hand-written encoder must be byte-identical to dart:convert's utf8.encode
// for every password shape, or the derived key would differ from the CLI's.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/native_utf8.dart';

void main() {
  group('native utf8 encoder', () {
    void expectMatchesUtf8Encode(String s) {
      final expected = utf8.encode(s);
      final len = utf8ByteLength(s);
      expect(len, expected.length, reason: 'byte length for ${s.runes.toList()}');
      final out = List<int>.filled(len, 0);
      final written = writeUtf8Native(s, out);
      expect(written, len);
      expect(out, expected, reason: 'bytes for ${s.runes.toList()}');
    }

    test('empty', () => expectMatchesUtf8Encode(''));

    test('ascii password', () => expectMatchesUtf8Encode('correct horse 123!'));

    test('2-byte UTF-8 (Latin/Greek)', () {
      expectMatchesUtf8Encode('pässwördΩ');
    });

    test('3-byte UTF-8 (CJK)', () {
      expectMatchesUtf8Encode('密码中文');
    });

    test('4-byte UTF-8 (supplementary, valid surrogate pair)', () {
      // U+1F600 is a valid lead+trail pair that runes() combines.
      expectMatchesUtf8Encode('pw😀x');
    });

    test('unpaired surrogates become U+FFFD like utf8.encode', () {
      // string.dart:716-717 -- runes() yields unpaired halves as-is; the
      // encoder must replace them to stay byte-identical to dart:convert.
      expectMatchesUtf8Encode(String.fromCharCode(0xD800));
      expectMatchesUtf8Encode(String.fromCharCode(0xDC00));
      expectMatchesUtf8Encode('a${String.fromCharCode(0xD800)}b');
    });

    test('mixed supplementary + BMP + ascii', () {
      expectMatchesUtf8Encode('aΩ中😀z\u{1D11E}');
    });
  });
}
