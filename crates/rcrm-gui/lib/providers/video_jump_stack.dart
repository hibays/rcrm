// providers/video_jump_stack.dart
// The video jump-history stack — the videos `Back` returns to, newest last.
//
// Deliberately a provider and not a field of the player screen's State:
//
//  * a jump REPLACES the player route (`Navigator.pushReplacement` in
//    `video_player_screen._go`), so a field would be born empty in the incoming
//    screen — the history has to outlive the State that recorded it;
//  * the Related list excludes the stack's entries
//    (`utils/related_videos.dart`), so the player screen and that computation
//    must read ONE observable source of truth, not two copies.
//
// What the stack holds: the video a jump is LEAVING. That is exactly the entry
// back returns to, so a forward jump records the current video and `Back` pops
// it and navigates there. The video being watched right now is never in the
// stack — `relatedFor` already drops it, and recording it would make `Back`
// return to the video it is already on.
//
// Session state: only the LIMIT is persisted (the `video_jump_history_limit`
// setting). A fresh launch starts with an empty stack.

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/media_item.dart';
import 'settings_provider.dart';

class VideoJumpStackNotifier extends Notifier<List<MediaItem>> {
  @override
  List<MediaItem> build() {
    // Lowering the limit (the settings slider) shrinks an existing stack from
    // the oldest end, exactly like pushing past the limit does.
    ref.listen(
      uiSettingsProvider.select((s) => s.videoJumpHistoryLimit),
      (_, _) => _trimToLimit(),
    );
    return const [];
  }

  /// How many entries are kept — read from the setting on every use rather than
  /// cached, so a restored or just-lowered limit applies to the very next push.
  int get limit => ref.read(uiSettingsProvider).videoJumpHistoryLimit;

  /// The entry `Back` would return to; null when there is nothing to return to
  /// (and `Back` therefore leaves the player as it always did).
  MediaItem? get top => state.isEmpty ? null : state.last;

  /// Records [item] — the video being left — as the next thing to return to.
  ///
  /// No de-duplication: jumping to a video that is already in the stack adds a
  /// second entry, so `Back` retraces the route that was actually taken (the
  /// same way a browser's history does).
  void push(MediaItem item) => state = _capped([...state, item]);

  /// Removes and returns the newest entry — what `Back` navigates to. Null when
  /// the stack is empty.
  MediaItem? pop() {
    if (state.isEmpty) return null;
    final last = state.last;
    state = state.sublist(0, state.length - 1);
    return last;
  }

  void clear() => state = const [];

  /// Drops the OLDEST entries while the stack is over [limit]: the newest are
  /// the ones `Back` reaches first, so they are the ones worth keeping.
  List<MediaItem> _capped(List<MediaItem> items) {
    final max = limit;
    if (items.length <= max) return items;
    return items.sublist(items.length - max);
  }

  void _trimToLimit() {
    final capped = _capped(state);
    // `_capped` returns its argument untouched when nothing is over the limit —
    // re-assigning the same list would only manufacture a rebuild.
    if (!identical(capped, state)) state = capped;
  }
}

final videoJumpStackProvider =
    NotifierProvider<VideoJumpStackNotifier, List<MediaItem>>(
      VideoJumpStackNotifier.new,
    );

/// The stack's paths as a set — the Related list's exclusion set, and the
/// "is there anything to go back to" question `PlayerControlBar.hasPrev` asks.
final jumpExcludedPathsProvider = Provider<Set<String>>(
  (ref) => {for (final v in ref.watch(videoJumpStackProvider)) v.path},
);
