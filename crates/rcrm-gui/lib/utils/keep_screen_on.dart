// utils/keep_screen_on.dart
// Whether the mobile player should hold the screen awake right now.
//
// ONE rule, in a pure function, because the screen that carries it out
// (`video_player_screen.dart`) cannot be mounted in a test. The rule is
// "awake while the file is PLAYING", not "awake for the whole fullscreen
// session": a viewer who pauses and puts the phone down is asking the system's
// own timeout to take over, which is what every player does by default. The
// setting only decides whether a PLAYING fullscreen video holds the screen --
// turning it off hands even that back to the system.
//
// Outside fullscreen a playing video still holds the screen, exactly as the
// engine's own `Video` widget did before this setting existed. Desktop is not
// part of this policy: its player keeps the engine's own wakelock, and the
// setting is not offered there (see `services/screen_wakelock.dart`).

/// Whether the player should keep the screen awake.
///
/// * [mobile] -- the two mobile platforms; a desktop player uses the engine's
///   own behaviour.
/// * [fullscreen] -- where the setting acts.
/// * [enabled] -- the stored "Keep Screen On" preference.
/// * [playing] -- the app's own belief that the file is rolling. A paused file
///   never holds the screen, in either mode.
bool shouldKeepScreenOn({
  required bool mobile,
  required bool fullscreen,
  required bool enabled,
  required bool playing,
}) {
  if (!mobile || !playing) return false;
  // A playing windowed video behaves as it always did; the switch is the only
  // thing that can release a PLAYING fullscreen one.
  return !fullscreen || enabled;
}

/// What the settings row promises, shown only while the player is fullscreen.
///
/// Static rather than a function of the switch: the paused half is not a
/// choice, it is the platform's own timeout, and saying so is the point.
const String keepScreenOnNote =
    'Keep the screen awake while the video is playing; a paused video lets the '
    'system timeout apply';
