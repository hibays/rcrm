// utils/player_panels.dart
// The player's "a panel owns the screen" rule, in one place.
//
// Settings, the episode sheet (the playlist) and the speed menu are panels: the
// user is working INSIDE them, not on the player. So every gesture that would
// otherwise reach the player must be refused while one of them is open — and
// there is more than one such gesture (the idle fade, the mouse wheel), which is
// why the rule lives here instead of being re-spelled at each call site.

/// Which panels the player screen currently has open.
class PlayerPanels {
  const PlayerPanels({
    this.settings = false,
    this.episodes = false,
    this.speedMenu = false,
  });

  /// The settings sheet (`_showSettings`).
  final bool settings;

  /// The episode sheet, a.k.a. the playlist (`_showEpisodes`).
  final bool episodes;

  /// The speed popup menu, which is a panel too (`_speedMenuOpen`).
  final bool speedMenu;

  bool get anyOpen => settings || episodes || speedMenu;
}
