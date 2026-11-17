// utils/keywords.dart
// RCrm GUI — heuristic keywords, tag index and relevance.
//
// A library's file names are already written by someone who wanted the content
// to be findable: title words, performers, studios, genres. Release tags and
// technical noise (1080p, x264, WEB-DL, 中文字幕) are the opposite — they say
// how the file was made, not what is in it. This file separates the two without
// a dictionary, then turns the survivors into:
//
//   * a per-item KeywordSet (its tags, weighted and normalised);
//   * a library KeywordIndex (which tags repeat, which videos carry them);
//   * a similarity/recommendation function used by the player's Related list
//     and the Home tab's channels.
//
// Everything here is pure and synchronous. The index is rebuilt from the
// scanned list; tokenisation is memoised per item by [KeywordExtractor] so a
// scan that grows by one folder does not re-tokenise the whole library.

import 'dart:math' as math;

import '../models/media_item.dart';
import 'natural_sort.dart';

/// One displayable tag: the normalised [key] used for comparisons, and the
/// [label] the user reads (the first spelling encountered, lightly title-cased).
class KeywordTag {
  final String key;
  final String label;

  const KeywordTag(this.key, this.label);

  @override
  bool operator ==(Object other) => other is KeywordTag && other.key == key;

  @override
  int get hashCode => key.hashCode;

  @override
  String toString() => label;
}

/// The tags of ONE item, strongest first.
///
/// [weights] are normalised so the item's strongest tag is 1.0; [sumSquares]
/// is the squared norm used by [similarityTo], so two sets can be compared
/// without walking their maps twice.
class KeywordSet {
  final List<KeywordTag> tags;
  final Map<String, double> weights;
  final double sumSquares;

  const KeywordSet._(this.tags, this.weights, this.sumSquares);

  static const empty = KeywordSet._(<KeywordTag>[], <String, double>{}, 0);

  bool get isEmpty => tags.isEmpty;
  bool get isNotEmpty => tags.isNotEmpty;

  /// The labels, strongest first — what the details sheet prints.
  List<String> get labels => [for (final t in tags) t.label];

  double weightOf(String key) => weights[key] ?? 0;

  bool contains(String key) => weights.containsKey(key);

  /// Weighted cosine similarity. Two sets that share the strongest tags score
  /// higher than two that merely share weak ones, and an empty set is never
  /// similar to anything (including another empty one).
  double similarityTo(KeywordSet other) {
    if (sumSquares == 0 || other.sumSquares == 0) return 0;
    final a = weights.length <= other.weights.length ? weights : other.weights;
    final b = identical(a, weights) ? other.weights : weights;
    var dot = 0.0;
    for (final entry in a.entries) {
      final w = b[entry.key];
      if (w != null) dot += entry.value * w;
    }
    if (dot == 0) return 0;
    return (dot / math.sqrt(sumSquares * other.sumSquares)).clamp(0.0, 1.0);
  }

  factory KeywordSet._from(
    Map<String, double> scores,
    Map<String, String> labels,
  ) {
    if (scores.isEmpty) return empty;
    final maxWeight = scores.values.reduce(math.max);
    if (maxWeight <= 0) return empty;

    final ranked =
        scores.entries.where((e) => e.value >= maxWeight * 0.18).toList()
          ..sort((a, b) {
            final byWeight = b.value.compareTo(a.value);
            if (byWeight != 0) return byWeight;
            return (labels[a.key] ?? a.key).toLowerCase().compareTo(
              (labels[b.key] ?? b.key).toLowerCase(),
            );
          });

    final tags = <KeywordTag>[];
    final weights = <String, double>{};
    var sumSquares = 0.0;
    for (final entry in ranked.take(8)) {
      final w = entry.value / maxWeight;
      weights[entry.key] = w;
      sumSquares += w * w;
      tags.add(KeywordTag(entry.key, labels[entry.key] ?? entry.key));
    }
    return KeywordSet._(tags, weights, sumSquares);
  }
}

/// One tag channel: the tag, the videos that carry it (strongest first, capped)
/// and how many there are in all.
class KeywordChannel {
  final KeywordTag tag;
  final List<MediaItem> items;
  final int itemCount;

  const KeywordChannel({
    required this.tag,
    required this.items,
    required this.itemCount,
  });

  String get label => tag.label;
}

/// Tokenises items, memoised by path. The same path is re-read on every scan
/// batch, and a library of tens of thousands of files makes that the one cost
/// worth caching.
class KeywordExtractor {
  final Map<String, KeywordSet> _cache = {};

  KeywordSet forItem(MediaItem item) {
    final hit = _cache[item.path];
    if (hit != null) return hit;
    if (_cache.length >= 50000) _cache.clear();
    final set = _extract(item);
    _cache[item.path] = set;
    return set;
  }

  KeywordSet _extract(MediaItem item) {
    final scores = <String, double>{};
    final labels = <String, String>{};

    final base = item.name.split(_pathSepRe).last;
    final stem = base.replaceFirst(_extensionRe, '');
    _scanText(stem, 1.0, scores, labels);

    // The folder is a weaker signal: it is often a series or studio name, but a
    // file name that already says what the content is must outrank it.
    final folder = item.albumName.isNotEmpty
        ? item.albumName
        : _parentFolderOf(item.path);
    if (folder.isNotEmpty && folder != '_root' && folder != '/') {
      _scanText(folder, 0.55, scores, labels);
    }
    return KeywordSet._from(scores, labels);
  }

  void _scanText(
    String text,
    double factor,
    Map<String, double> scores,
    Map<String, String> labels,
  ) {
    final cleaned = text
        .replaceAll(_httpRe, ' ')
        .replaceAll(_wwwRe, ' ')
        .replaceAll(_domainRe, ' ');

    final latin = <String>[];
    for (final match in _runRe.allMatches(cleaned)) {
      final run = match.group(0)!;
      if (_isCjk(run.codeUnitAt(0))) {
        _addCjk(run, factor, scores, labels);
      } else {
        latin.addAll(_splitLatin(run));
      }
    }
    for (var i = 0; i < latin.length; i++) {
      // Earlier words in a name are usually the title; later ones drift into
      // release-group and episode markers. The 1.0 → 0.65 ramp is small enough
      // that a repeated later word still survives.
      final position = latin.length == 1 ? 0.0 : i / (latin.length - 1);
      _addLatin(latin[i], factor * (1.0 - 0.35 * position), scores, labels);
    }
  }

  void _addLatin(
    String raw,
    double weight,
    Map<String, double> scores,
    Map<String, String> labels,
  ) {
    if (!_plausibleLatin(raw)) return;
    final key = raw.toLowerCase();
    scores[key] = (scores[key] ?? 0) + weight;
    labels.putIfAbsent(key, () => _displayLatin(raw));
  }

  void _addCjk(
    String run,
    double factor,
    Map<String, double> scores,
    Map<String, String> labels,
  ) {
    var cleaned = run.replaceAll(_cjkNoiseRe, '');
    cleaned = cleaned.replaceAll(_cjkEpisodeRe, '');
    if (cleaned.length < 2) return;

    // A short run is one word to a reader ("国产", "剧情演绎") and stays whole.
    // A longer one is a phrase with no spaces, so non-overlapping two-character
    // chunks are the useful subset: "中文字幕" becomes "中文" + "字幕" without
    // the "文字" that overlaps both. The whole run is kept only while it is
    // short enough to read as a tag rather than a sentence.
    if (cleaned.length <= 6) {
      _addCjkTag(cleaned, factor, scores, labels);
    } else if (cleaned.length <= 8) {
      _addCjkTag(cleaned, factor * 0.85, scores, labels);
    }
    if (cleaned.length >= 4) {
      for (var i = 0; i + 2 <= cleaned.length; i += 2) {
        _addCjkTag(cleaned.substring(i, i + 2), factor * 0.55, scores, labels);
      }
    }
  }

  void _addCjkTag(
    String tag,
    double weight,
    Map<String, double> scores,
    Map<String, String> labels,
  ) {
    if (tag.length < 2) return;
    scores[tag] = (scores[tag] ?? 0) + weight;
    labels.putIfAbsent(tag, () => tag);
  }

  static List<String> _splitLatin(String run) {
    var s = run.replaceAllMapped(_camelSplitRe, (m) => '${m[1]} ${m[2]}');
    s = s.replaceAllMapped(_letterDigitRe, (m) => '${m[1]} ${m[2]}');
    s = s.replaceAllMapped(_digitLetterRe, (m) => '${m[1]} ${m[2]}');
    return s.split(_spaceRe).where((t) => t.isNotEmpty).toList();
  }

  static bool _plausibleLatin(String token) {
    final low = token.toLowerCase();
    if (low.length < 2 || low.length > 24) return false;
    if (_pureDigits.hasMatch(low)) return false;
    if (_resolutionToken.hasMatch(low)) return false;
    if (_episodeToken.hasMatch(low)) return false;
    if (_latinNoise.contains(low)) return false;
    // A one- to three-letter stem with a number ("a1", "v2") is a marker, not a
    // word. Real titles may still be short ("up"), so only the digit shape is
    // rejected and the stop list handles the rest.
    if (_markerTokenRe.hasMatch(low)) return false;
    return true;
  }

  static String _displayLatin(String raw) {
    if (raw != raw.toLowerCase()) {
      return raw; // keep an acronym or a proper name
    }
    if (raw.isEmpty) return raw;
    return '${raw[0].toUpperCase()}${raw.substring(1)}';
  }

  static String _parentFolderOf(String path) {
    final p = path.replaceAll('\\', '/');
    final cut = p.lastIndexOf('/');
    if (cut <= 0) return '';
    final parent = p.substring(0, cut);
    final parentCut = parent.lastIndexOf('/');
    return parentCut < 0 ? parent : parent.substring(parentCut + 1);
  }
}

/// The library-wide view: every item's tags, which tags repeat, and the tag
/// channels the Home tab can offer.
class KeywordIndex {
  final Map<String, KeywordSet> _sets;
  final Map<String, MediaItem> _items;
  final Map<String, int> _counts;
  final Map<String, String> _labels;
  final List<KeywordTag> _top;

  KeywordIndex._(
    this._sets,
    this._items,
    this._counts,
    this._labels,
    this._top,
  );

  static final empty = KeywordIndex._(
    const {},
    const {},
    const {},
    const {},
    const [],
  );

  factory KeywordIndex.build(
    Iterable<MediaItem> videos, {
    KeywordExtractor? extractor,
  }) {
    final ex = extractor ?? KeywordExtractor();
    final sets = <String, KeywordSet>{};
    final items = <String, MediaItem>{};
    final counts = <String, int>{};
    final totals = <String, double>{};
    final labels = <String, String>{};

    for (final video in videos) {
      final set = ex.forItem(video);
      sets[video.path] = set;
      items[video.path] = video;
      for (final tag in set.tags) {
        counts[tag.key] = (counts[tag.key] ?? 0) + 1;
        totals[tag.key] = (totals[tag.key] ?? 0) + set.weightOf(tag.key);
        labels.putIfAbsent(tag.key, () => tag.label);
      }
    }

    final top =
        <KeywordTag>[
          for (final entry in counts.entries)
            if (entry.value >= 2)
              KeywordTag(entry.key, labels[entry.key] ?? entry.key),
        ]..sort((a, b) {
          final byCount = (counts[b.key] ?? 0).compareTo(counts[a.key] ?? 0);
          if (byCount != 0) return byCount;
          final byWeight = (totals[b.key] ?? 0).compareTo(totals[a.key] ?? 0);
          if (byWeight != 0) return byWeight;
          return (labels[a.key] ?? a.key).toLowerCase().compareTo(
            (labels[b.key] ?? b.key).toLowerCase(),
          );
        });

    return KeywordIndex._(
      sets,
      items,
      counts,
      labels,
      List<KeywordTag>.unmodifiable(top.take(32)),
    );
  }

  bool get isEmpty => _sets.isEmpty;

  KeywordSet setFor(String path) => _sets[path] ?? KeywordSet.empty;

  /// The repeated tags, strongest first. A tag must appear on at least two
  /// files to be a filter or a channel: a keyword on one file is a description,
  /// not a way to browse.
  List<KeywordTag> get topTags => _top;

  List<KeywordTag> topTagsLimited(int limit) =>
      List<KeywordTag>.unmodifiable(_top.take(limit));

  /// Tags that co-occur with [keys] in the files that carry ALL of them.
  ///
  /// This is the recommendation under a '#tag' search: the next tag the viewer
  /// is most likely to add, drawn from the files the current tags already
  /// match. Compiled from the same per-file sets the filters use, so a tag that
  /// is too weak to enter [topTags] can still be a useful related tag.
  List<KeywordTag> relatedTags(Iterable<String> keys, {int limit = 8}) {
    final selected = keys.toSet();
    if (selected.isEmpty) return const [];
    final counts = <String, int>{};
    final weights = <String, double>{};
    for (final set in _sets.values) {
      if (!selected.every(set.contains)) continue;
      for (final tag in set.tags) {
        if (selected.contains(tag.key)) continue;
        counts[tag.key] = (counts[tag.key] ?? 0) + 1;
        weights[tag.key] = (weights[tag.key] ?? 0) + set.weightOf(tag.key);
      }
    }
    final related =
        <KeywordTag>[
          for (final entry in counts.entries)
            KeywordTag(entry.key, _labels[entry.key] ?? entry.key),
        ]..sort((a, b) {
          final byCount = (counts[b.key] ?? 0).compareTo(counts[a.key] ?? 0);
          if (byCount != 0) return byCount;
          final byWeight = (weights[b.key] ?? 0).compareTo(weights[a.key] ?? 0);
          if (byWeight != 0) return byWeight;
          return (_labels[a.key] ?? a.key).toLowerCase().compareTo(
            (_labels[b.key] ?? b.key).toLowerCase(),
          );
        });
    return List<KeywordTag>.unmodifiable(related.take(limit));
  }

  int countFor(String key) => _counts[key] ?? 0;

  String labelFor(String key) {
    final label = _labels[key];
    if (label != null) return label;
    if (key.isEmpty) return key;
    return '${key[0].toUpperCase()}${key.substring(1)}';
  }

  /// The tag channels, strongest first. [minItems] is the point at which a tag
  /// becomes a section rather than a label; [perChannel] caps each row.
  List<KeywordChannel> channels({
    int minItems = 2,
    int max = 3,
    int perChannel = 12,
  }) {
    final chosen = <KeywordTag>[
      for (final tag in _top)
        if (countFor(tag.key) >= minItems) tag,
    ].take(max);

    final out = <KeywordChannel>[];
    for (final tag in chosen) {
      final hits = <({MediaItem item, double weight})>[];
      for (final entry in _sets.entries) {
        final w = entry.value.weightOf(tag.key);
        if (w <= 0) continue;
        final item = _items[entry.key];
        if (item != null) hits.add((item: item, weight: w));
      }
      hits.sort((a, b) {
        final byWeight = b.weight.compareTo(a.weight);
        if (byWeight != 0) return byWeight;
        return naturalCompare(a.item.name, b.item.name);
      });
      out.add(
        KeywordChannel(
          tag: tag,
          items: List<MediaItem>.unmodifiable(
            hits.take(perChannel).map((h) => h.item),
          ),
          itemCount: hits.length,
        ),
      );
    }
    return List<KeywordChannel>.unmodifiable(out);
  }
}

/// The Home tab's Recommended row.
///
/// With [relevance] at 0 this is the old day-seeded shuffle (the jitter is the
/// only term left); as it rises, the row first follows the viewer's recent
/// tags and then the library's own channels. Recently played videos are pushed
/// down rather than removed, so a small library still fills the row.
List<MediaItem> keywordRecommendations(
  KeywordIndex index,
  List<MediaItem> videos, {
  required List<MediaItem> recent,
  required int daySeed,
  required int relevance,
  int limit = 10,
}) {
  if (videos.isEmpty) return const [];
  final influence = relevance.clamp(0, 100) / 100.0;
  final profile = <String, double>{};
  for (final video in recent.take(10)) {
    final set = index.setFor(video.path);
    for (final tag in set.tags) {
      final w = set.weightOf(tag.key);
      if (w > (profile[tag.key] ?? 0)) profile[tag.key] = w;
    }
  }

  final top = index.topTagsLimited(10);
  final topMax = top.isEmpty ? 1 : math.max(1, index.countFor(top.first.key));
  final recentPaths = {for (final v in recent) v.path};

  final ranked = <({MediaItem item, double score})>[];
  for (final video in videos) {
    final set = index.setFor(video.path);
    final personal = _profileSimilarity(profile, set);
    final channel = _channelScore(index, set, top, topMax);
    final jitter = math.Random(daySeed ^ _pathHash(video.path)).nextDouble();
    var score =
        personal * 2.5 * influence + channel * 0.8 * influence + jitter * 0.6;
    if (recentPaths.contains(video.path)) score -= 0.45;
    ranked.add((item: video, score: score));
  }

  ranked.sort((a, b) {
    final byScore = b.score.compareTo(a.score);
    if (byScore != 0) return byScore;
    return naturalCompare(a.item.name, b.item.name);
  });
  return List<MediaItem>.unmodifiable(ranked.take(limit).map((r) => r.item));
}

double _profileSimilarity(Map<String, double> profile, KeywordSet set) {
  if (profile.isEmpty || set.sumSquares == 0) return 0;
  var dot = 0.0;
  var norm = 0.0;
  for (final entry in profile.entries) {
    norm += entry.value * entry.value;
    final w = set.weightOf(entry.key);
    if (w > 0) dot += entry.value * w;
  }
  if (dot == 0 || norm == 0) return 0;
  return (dot / math.sqrt(norm * set.sumSquares)).clamp(0.0, 1.0);
}

double _channelScore(
  KeywordIndex index,
  KeywordSet set,
  List<KeywordTag> top,
  int topMax,
) {
  if (top.isEmpty) return 0;
  var sum = 0.0;
  for (final tag in top) {
    final w = set.weightOf(tag.key);
    if (w <= 0) continue;
    sum += w * (index.countFor(tag.key) / topMax);
  }
  return (sum / top.length).clamp(0.0, 1.0);
}

int _pathHash(String s) {
  var h = 0x811c9dc5;
  for (final c in s.codeUnits) {
    h ^= c;
    h = (h * 0x01000193) & 0x7fffffff;
  }
  return h;
}

// ── Token rules ──────────────────────────────────────────────
//
// Compiled once. These run per file name, and a library can hold tens of
// thousands of names; constructing a RegExp inside the loop was measurable
// work for no benefit.

final RegExp _pathSepRe = RegExp(r'[/\\]');
final RegExp _extensionRe = RegExp(r'\.[A-Za-z0-9]{1,5}$');
final RegExp _httpRe = RegExp(r'https?://\S+', caseSensitive: false);
final RegExp _wwwRe = RegExp(r'www\.\S+', caseSensitive: false);
final RegExp _domainRe = RegExp(
  r'\b[\w-]+\.(?:com|net|org|cc|tv|xyz|me|top|info|io)\b',
  caseSensitive: false,
);
final RegExp _cjkEpisodeRe = RegExp(r'第[一二三四五六七八九十百千万\d]+[集季部期话]');
final RegExp _camelSplitRe = RegExp(r'([a-z0-9])([A-Z])');
final RegExp _letterDigitRe = RegExp(r'([A-Za-z])(\d)');
final RegExp _digitLetterRe = RegExp(r'(\d)([A-Za-z])');
final RegExp _spaceRe = RegExp(r'\s+');
final RegExp _markerTokenRe = RegExp(r'^[A-Za-z]{1,3}\d+$');

final RegExp _runRe = RegExp(
  // Latin (including accented), Greek and Cyrillic words, then CJK/Hangul.
  // A title in any of these scripts is still a word per separator, not a
  // character soup.
  r'[A-Za-z0-9\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF]+|'
  r'[\u3040-\u30FF\u3400-\u4DBF\u4E00-\u9FFF\uAC00-\uD7AF\uF900-\uFAFF]+',
);
final RegExp _pureDigits = RegExp(r'^\d+$');
final RegExp _resolutionToken = RegExp(r'^\d+[pik]$');
final RegExp _episodeToken = RegExp(
  r'^(?:s\d{1,2}e\d{1,3}|e\d{1,3}|ep?\d{1,3}|part\d{1,3}|cd\d{1,2}|disc\d{1,2}|vol\d{1,3}|season\d{1,3})$',
);

bool _isCjk(int c) =>
    (c >= 0x3040 && c <= 0x30ff) ||
    (c >= 0x3400 && c <= 0x4dbf) ||
    (c >= 0x4e00 && c <= 0x9fff) ||
    (c >= 0xac00 && c <= 0xd7af) ||
    (c >= 0xf900 && c <= 0xfaff);

const Set<String> _latinNoise = <String>{
  'the',
  'and',
  'for',
  'with',
  'from',
  'this',
  'that',
  'these',
  'those',
  'you',
  'your',
  'our',
  'his',
  'her',
  'its',
  'they',
  'them',
  'are',
  'was',
  'were',
  'been',
  'being',
  'have',
  'has',
  'had',
  'will',
  'would',
  'can',
  'could',
  'may',
  'might',
  'must',
  'not',
  'all',
  'any',
  'some',
  'more',
  'most',
  'other',
  'into',
  'over',
  'under',
  'after',
  'before',
  'than',
  'then',
  'when',
  'where',
  'who',
  'how',
  'why',
  'part',
  'parts',
  'full',
  'complete',
  'version',
  'ver',
  'final',
  'new',
  'old',
  'original',
  'extended',
  'remastered',
  'restored',
  'edition',
  'cut',
  'scene',
  'clip',
  'video',
  'videos',
  'movie',
  'movies',
  'film',
  'films',
  'footage',
  'episode',
  'episodes',
  'ep',
  'eps',
  'season',
  'series',
  'volume',
  'vol',
  'disc',
  'disk',
  'cd',
  'dvd',
  'bluray',
  'blu',
  'ray',
  'web',
  'webrip',
  'webdl',
  'dl',
  'hdtv',
  'hdcam',
  'cam',
  'ts',
  'tc',
  'hdrip',
  'dvdrip',
  'brrip',
  'bdrip',
  'remux',
  'x264',
  'x265',
  'h264',
  'h265',
  'hevc',
  'avc',
  'av1',
  'vp8',
  'vp9',
  'xvid',
  'divx',
  'mpeg',
  'mpg',
  'mp4',
  'mkv',
  'avi',
  'mov',
  'wmv',
  'flv',
  'webm',
  'm4v',
  'aac',
  'ac3',
  'eac3',
  'dts',
  'flac',
  'mp3',
  'opus',
  'ogg',
  'wav',
  'truehd',
  'atmos',
  'ddp',
  'dd',
  'lpcm',
  'hdr',
  'hdr10',
  'sdr',
  'dolby',
  'vision',
  'uhd',
  'fhd',
  'hd',
  'sd',
  'hq',
  'mq',
  'lq',
  '4k',
  '8k',
  '2k',
  '1080p',
  '1080i',
  '720p',
  '720i',
  '2160p',
  '1440p',
  '480p',
  '360p',
  '540p',
  '8bit',
  '10bit',
  '12bit',
  'fps',
  'sub',
  'subs',
  'subtitle',
  'subtitles',
  'subtitled',
  'dub',
  'dubbed',
  'dual',
  'multi',
  'multilingual',
  'hardsub',
  'softsub',
  'chs',
  'cht',
  'eng',
  'jpn',
  'kor',
  'chinese',
  'english',
  'japanese',
  'korean',
  'www',
  'com',
  'net',
  'org',
  'cc',
  'tv',
  'xyz',
  'top',
  'info',
  'io',
  'site',
  'download',
  'downloads',
  'free',
  'online',
  'watch',
  'stream',
  'streaming',
  'group',
  'release',
  'rips',
  'rip',
  'sample',
  'trailer',
  'teaser',
  'preview',
  'bonus',
  'extra',
  'extras',
  'bts',
  'behind',
  'scenes',
  'uncut',
  'censored',
  'uncensored',
};

const List<String> _cjkNoise = <String>[
  '中文字幕',
  '高清版',
  '完整版',
  '未删减',
  '无删减',
  '中字',
  '字幕',
  '高清',
  '超清',
  '蓝光',
  '标清',
  '原画',
  '双语',
  '合集',
  '全集',
  '系列',
  '更新',
  '最新',
  '视频',
  '影片',
  '电影',
  '在线',
  '观看',
  '下载',
  '免费',
  '精品',
  '完整',
  '修复',
  '重制',
  '独家',
  '首发',
  '官方',
  '出品',
  '制作',
];

final RegExp _cjkNoiseRe = RegExp(
  (List<String>.from(
    _cjkNoise,
  )..sort((a, b) => b.length.compareTo(a.length))).map(RegExp.escape).join('|'),
);
