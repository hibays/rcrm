// utils/ffmpeg_thumb_args.dart
// The desktop VIDEO THUMBNAIL poster's ffmpeg command line, as a pure function.
//
// `ThumbnailService._posterDesktop` used to build this list inline, twice (once
// per seek mode), which made the ordering unobservable: nothing could assert
// that `-tls_verify 0` sits *before* the `-i` it applies to, or that
// `-hide_banner` is the first thing ffmpeg sees. Order is the whole point of
// these options — an input option placed after `-i` is silently ignored, and one
// whose name the input's protocol does not define is FATAL — so the assembly is
// separated here, the same reason `admitPosterJob` and `planPosterKick` live in
// `poster_queue.dart`.
//
// Two placements are load-bearing:
//
// * `-hide_banner` is GLOBAL: it must precede the first input.
// * `-tls_verify 0` is an input option *of the `tls` protocol*, so it is emitted
//   only for an `https://` URL. The measurements behind that condition are on
//   the option itself below.

/// Build the ffmpeg argv for one video thumbnail (poster) frame from [url].
///
/// [inputSeek] selects where `-ss` goes, which is the behaviour this preserves:
/// as an input option (before `-i`, fast — ffmpeg seeks the container) or as an
/// output option (after `-i`, accurate — ffmpeg decodes up to the timestamp).
/// The caller tries one then the other.
///
/// [width] is the poster width; `-vf scale=$width:-1` keeps the aspect ratio and
/// emits a JPEG on stdout (`-f image2 -c:v mjpeg pipe:1`), so the caller reads
/// bytes from a pipe and never writes plaintext to disk.
///
/// Every entry is a separate argv element: `-headers "Authorization: Basic …"`
/// reaches ffmpeg as one argument, so the credentials never appear in the URL
/// (see `ThumbnailService.safeUrl`) and no shell is involved.
List<String> ffmpegThumbArgs({
  required String url,
  required Map<String, String> headers,
  required double seekSeconds,
  required int frames,
  required int width,
  required bool inputSeek,
}) {
  assert(frames > 0, 'a video thumbnail is at least one frame');
  final relaxTlsVerify = Uri.tryParse(url)?.scheme.toLowerCase() == 'https';
  return [
    // Global options, before any input.
    '-hide_banner',
    // ── Input options: everything here applies to the `-i` below ──
    //
    // SCOPED *AND CONDITIONAL* RELAXATION. RCrm's own server presents a
    // self-signed certificate and the app pins certificates in its Dart HTTP
    // client (`net.dart` `createTrustAwareHttpClient`, session-scoped SHA-1 pin
    // — every other cert is refused); ffmpeg has no way to know about that pin,
    // so its own verification is turned off for this one fetch path — the video
    // thumbnail subprocess — and nothing else. ffmpeg ≥ 9 flipped the default to
    // `tls_verify=1`, which is why thumbnails over https:// started failing:
    // "[tls @ …] Peer certificate failed verification" → "Error opening input:
    // I/O error".
    //
    // `https://` ONLY, and that is not a nicety. ffmpeg resolves the *name* of an
    // input option against the protocol the URL selects — after choosing it — and
    // a name that protocol does not define aborts the entire command:
    //
    //   file:     + flag  → "Option tls_verify not found."  exit ≠ 0, no output
    //   http://   + flag  → "Option tls_verify not found."  exit ≠ 0, no output
    //   http://   no flag → exit 0, JPEG
    //   https://  + flag  → exit 0, JPEG
    //   https://  no flag → exit -5, "Peer certificate failed verification"
    //
    // (measured on this machine's ffmpeg 9.0.2, one file served over both
    // schemes). The desktop app's own server is `http://127.0.0.1:<port>`, so an
    // unconditional flag leaves *every* poster empty; a missing flag breaks only
    // the https ones. Hence the scheme decides.
    if (relaxTlsVerify) ...['-tls_verify', '0'],
    if (headers.isNotEmpty) ...[
      '-headers',
      headers.entries.map((e) => '${e.key}: ${e.value}').join('\r\n'),
    ],
    if (inputSeek) ...['-ss', seekSeconds.toString()],
    '-an',
    '-i',
    url,
    // ── Output options: the frame itself ──
    if (!inputSeek) ...['-ss', seekSeconds.toString()],
    '-vframes',
    frames.toString(),
    '-q:v',
    '3',
    '-vf',
    'scale=$width:-1',
    '-f',
    'image2',
    '-c:v',
    'mjpeg',
    'pipe:1',
  ];
}
