// utils/native_utf8.dart
// UTF-8 encode a Dart String straight into a caller-provided native buffer.
//
// Dart Strings are UTF-16 on the managed heap (string.dart:57) and cannot be
// borrowed from Rust. `package:ffi`'s `toNativeUtf8()` allocates a Dart-heap
// Uint8List first and copies it into native memory, leaving an unzeroized copy
// behind. These two functions do the encode in ONE pass into the final native
// buffer, so the only copy of the password bytes is the one Rust takes
// ownership of.
//
// Encoding matches `dart:convert`'s `utf8.encode` byte-for-byte, including the
// replacement of unpaired UTF-16 surrogates with U+FFFD (string.dart:716-717
// says `runes` yields unpaired halves as-is, so we handle them ourselves).

/// Exact number of UTF-8 bytes [text] encodes to. Call this first, then
/// allocate exactly that many bytes and pass them to [writeUtf8Native].
int utf8ByteLength(String text) {
  var n = 0;
  for (final rune in text.runes) {
    if (rune < 0x80) {
      n += 1;
    } else if (rune < 0x800) {
      n += 2;
    } else if (rune >= 0xD800 && rune <= 0xDFFF) {
      // Unpaired surrogate -> U+FFFD (EF BF BD), as utf8.encode does.
      n += 3;
    } else if (rune < 0x10000) {
      n += 3;
    } else {
      n += 4;
    }
  }
  return n;
}

/// Write the UTF-8 bytes of [text] into [out]. [out] must have exactly
/// [utf8ByteLength] bytes. Returns the number of bytes written.
int writeUtf8Native(String text, List<int> out) {
  var i = 0;
  for (final rune in text.runes) {
    if (rune < 0x80) {
      out[i++] = rune;
    } else if (rune < 0x800) {
      out[i++] = 0xC0 | (rune >> 6);
      out[i++] = 0x80 | (rune & 0x3F);
    } else if (rune >= 0xD800 && rune <= 0xDFFF) {
      // Unpaired surrogate -> U+FFFD, matching dart:convert.
      out[i++] = 0xEF;
      out[i++] = 0xBF;
      out[i++] = 0xBD;
    } else if (rune < 0x10000) {
      out[i++] = 0xE0 | (rune >> 12);
      out[i++] = 0x80 | ((rune >> 6) & 0x3F);
      out[i++] = 0x80 | (rune & 0x3F);
    } else {
      out[i++] = 0xF0 | (rune >> 18);
      out[i++] = 0x80 | ((rune >> 12) & 0x3F);
      out[i++] = 0x80 | ((rune >> 6) & 0x3F);
      out[i++] = 0x80 | (rune & 0x3F);
    }
  }
  return i;
}
