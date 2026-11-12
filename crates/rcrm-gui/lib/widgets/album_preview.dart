// widgets/album_preview.dart
// RCrm GUI — shared 2×2 album preview grid
//
// Used by AlbumCard (photo page) and album chips (home page) to
// render a consistent multi-image preview. Handles 1–4 images.

import 'package:flutter/material.dart';
import '../config/theme.dart';
import 'pooled_image.dart';

class AlbumPreview extends StatelessWidget {
  final List<String> urls;

  const AlbumPreview({super.key, required this.urls});

  @override
  Widget build(BuildContext context) {
    if (urls.isEmpty) {
      return Container(
        color: RCrmColors.coal,
        child: Center(
          child: Icon(Icons.folder, size: 48, color: RCrmColors.textFaint),
        ),
      );
    }

    if (urls.length == 1) {
      return _cell(urls[0]);
    }

    // 2×2 grid
    return Column(
      children: [
        Expanded(
          child: Row(
            children: [
              Expanded(child: _cell(urls[0])),
              if (urls.length > 1) Expanded(child: _cell(urls[1])),
            ],
          ),
        ),
        if (urls.length > 2)
          Expanded(
            child: Row(
              children: [
                Expanded(child: _cell(urls[2])),
                if (urls.length > 3)
                  Expanded(child: _cell(urls[3]))
                else
                  const Expanded(child: SizedBox()),
              ],
            ),
          ),
      ],
    );
  }

  Widget _cell(String url) {
    return PooledImage(
      url: url,
      fit: BoxFit.cover,
      decodeWidth: 400,
      placeholder: Container(color: RCrmColors.coal),
      errorWidget: Container(
        color: RCrmColors.coal,
        child: Icon(Icons.image, color: RCrmColors.textFaint),
      ),
    );
  }
}
