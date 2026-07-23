// widgets/album_preview.dart
// RCrm GUI — shared 2×2 album preview grid
//
// Used by AlbumCard (photo page) and album chips (home page) to
// render a consistent multi-image preview. Handles 1–4 images.

import 'package:flutter/material.dart';
import 'pooled_image.dart';

class AlbumPreview extends StatelessWidget {
  final List<String> urls;

  const AlbumPreview({super.key, required this.urls});

  @override
  Widget build(BuildContext context) {
    if (urls.isEmpty) {
      return Container(
        color: const Color(0xFF2A2A2A),
        child: const Center(
          child: Icon(Icons.folder, size: 48, color: Colors.white38),
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
      placeholder: Container(color: const Color(0xFF2A2A2A)),
      errorWidget: Container(
        color: const Color(0xFF2A2A2A),
        child: const Icon(Icons.image, color: Colors.white24),
      ),
    );
  }
}
