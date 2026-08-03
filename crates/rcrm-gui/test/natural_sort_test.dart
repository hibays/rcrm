// Natural sort (Windows-Explorer-style) unit tests.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/natural_sort.dart';

void main() {
  List<String> sorted(List<String> input) =>
      (List<String>.of(input)..sort(naturalCompare));

  test('the reported case: (49).jpg (5).jpg (51).jpg', () {
    expect(sorted(['(51).jpg', '(5).jpg', '(49).jpg']), [
      '(5).jpg',
      '(49).jpg',
      '(51).jpg',
    ]);
  });

  test('numbers compare numerically, not by digit count', () {
    // '-' (0x2D) < '.' (0x2E), so "2-2.jpg" precedes "2.jpg" — same as a
    // plain character comparison after the equal "2" run.
    expect(sorted(['2.jpg', '10.jpg', '1.jpg', '2-2.jpg']), [
      '1.jpg',
      '2-2.jpg',
      '2.jpg',
      '10.jpg',
    ]);
  });

  test('leading zeros are ignored ("007" == "7")', () {
    expect(sorted(['7.jpg', '007.jpg', '8.jpg']), [
      '7.jpg',
      '007.jpg',
      '8.jpg',
    ]);
  });

  test('case-insensitive letters; uppercase wins the tie', () {
    expect(sorted(['b.jpg', 'A.jpg', 'a.jpg']), ['A.jpg', 'a.jpg', 'b.jpg']);
  });

  test('digits sort before letters', () {
    expect(sorted(['a1.jpg', '1.jpg']), ['1.jpg', 'a1.jpg']);
  });

  test('shorter string sorts first', () {
    expect(sorted(['a1.jpg', 'a.jpg']), ['a.jpg', 'a1.jpg']);
  });

  test('mixed media filename patterns', () {
    expect(sorted(['IMG_10.jpg', 'IMG_2.jpg', 'IMG_02.jpg', 'IMG_1.jpg']), [
      'IMG_1.jpg',
      'IMG_2.jpg',
      'IMG_02.jpg',
      'IMG_10.jpg',
    ]);
  });

  test('albums with names', () {
    expect(sorted(['相册10', '相册2', '相册1']), ['相册1', '相册2', '相册10']);
  });

  test('cjk chars compare by code unit (deterministic, not pinyin)', () {
    // 册 U+518C < 片 U+7247 → 相册 < 相片
    expect(sorted(['相片.jpg', '相册.jpg']), ['相册.jpg', '相片.jpg']);
  });

  test('cjk + numeric runs mix', () {
    expect(sorted(['照片10.jpg', '照片2.jpg', '照片1.jpg']), [
      '照片1.jpg',
      '照片2.jpg',
      '照片10.jpg',
    ]);
  });

  test('surrogate pairs (ext-B / emoji) sort by code point', () {
    // U+20000 (𠀀) > U+1F600 (😀); shared prefix keeps them adjacent.
    expect(sorted(['a😀b', 'a𠀀b']), ['a😀b', 'a𠀀b']);
    expect(sorted(['a𠀀2', 'a𠀀10']), ['a𠀀2', 'a𠀀10']);
  });
}
