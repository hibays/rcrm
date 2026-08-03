// utils/natural_sort.dart
// Windows-Explorer-style (StrCmpLogicalW) natural string comparison.
//
// Embedded digit runs compare numerically, so "(2).jpg" < "(10).jpg" and
// "IMG_5.jpg" < "IMG_49.jpg" — the plain lexicographic `compareTo` would
// order "(49).jpg" before "(5).jpg" (classic dictionary-order surprise).
//
// Rules (mirror Explorer):
//   • digit runs compare as numbers (leading zeros ignored: "007" == "7")
//   • digits sort before letters, punctuation before digits
//   • letters compare case-insensitively; ties break uppercase-first
//   • a string that ends first sorts first ("a" < "a1")
//
// Hot-path tuned for media filenames: zero function calls per character,
// a single ASCII-letter fast path (the common case), digit runs scanned
// inline. An album sort does ~10⁵-10⁶ character comparisons, so this shows
// up during library scans and album opens.

int naturalCompare(String a, String b) {
  var i = 0, j = 0;
  final la = a.length, lb = b.length;
  while (i < la && j < lb) {
    final ca = a.codeUnitAt(i), cb = b.codeUnitAt(j);
    // ASCII-letter fast path: case-fold via |0x20 (exactly A-Z/a-z), tie-
    // break on the raw code unit (uppercase first, like Explorer).
    if ((ca | 0x20) >= 0x61 &&
        (ca | 0x20) <= 0x7A &&
        (cb | 0x20) >= 0x61 &&
        (cb | 0x20) <= 0x7A) {
      final d = (ca | 0x20) - (cb | 0x20);
      if (d != 0) return d;
      final dRaw = ca - cb;
      if (dRaw != 0) return dRaw;
      i++;
      j++;
      continue;
    }
    final da = ca >= 0x30 && ca <= 0x39;
    final db = cb >= 0x30 && cb <= 0x39;
    if (da && db) {
      // Skip leading zeros, then compare by significant-digit length and
      // digit-by-digit. All-zero runs are just 0 ("0" == "00").
      var si = i, sj = j;
      while (si < la && a.codeUnitAt(si) == 0x30) {
        si++;
      }
      while (sj < lb && b.codeUnitAt(sj) == 0x30) {
        sj++;
      }
      var ei = si, ej = sj;
      while (ei < la) {
        final u = a.codeUnitAt(ei);
        if (u < 0x30 || u > 0x39) break;
        ei++;
      }
      while (ej < lb) {
        final u = b.codeUnitAt(ej);
        if (u < 0x30 || u > 0x39) break;
        ej++;
      }
      final n1 = ei - si, n2 = ej - sj;
      if (n1 != n2) return n1 - n2;
      for (var k = 0; k < n1; k++) {
        final d = a.codeUnitAt(si + k) - b.codeUnitAt(sj + k);
        if (d != 0) return d;
      }
      i = ei;
      j = ej;
    } else if (da != db) {
      // Explorer: digits sort before letters ("1" < "a"), but punctuation
      // sorts before digits ("a." < "a1", "(5)." < "(51).").
      final other = da ? cb : ca;
      final otherIsLetter = (other | 0x20) >= 0x61 && (other | 0x20) <= 0x7A;
      if (otherIsLetter) return da ? -1 : 1;
      return da ? 1 : -1;
    } else {
      final d = ca - cb;
      if (d != 0) return d;
      i++;
      j++;
    }
  }
  return (la - i) - (lb - j);
}
