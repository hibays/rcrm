// utils/player_exit.dart
// "Return to the library": where the player's chain of routes lands, as a
// decision rather than a sequence of Navigator calls.
//
// Why this is not simply `Navigator.pop`: the player is reached by a push from
// the library shell (three sites — `home_screen`, `video_screen`'s grid,
// `search_screen`), and every jump inside the player REPLACES the player route
// (`video_player_screen._go`), so when the user asks to go home there is no
// single "the player route" to pop. The chain is `library → search? → player`,
// and one replacement replaced the player in place. Unwinding it is
// `Navigator.popUntil`, and this file is its predicate.
//
// `popUntil` pops every route the predicate rejects, walking from the top: a
// predicate that matches NOTHING pops the last route too, and an empty navigator
// is a black screen with no way back. That is why the landing rule has two
// clauses — the library by name, and the navigator's first route as a floor that
// is always true somewhere on the chain.
//
// The rule lives here, as a pure function over plain values, because the player
// screen cannot be mounted in a test: it creates a real media_kit `Player` in
// its first frame, so its navigation paths have no other seam.

import 'package:flutter/widgets.dart';

/// The library shell's route name — `app.dart`'s `routes` map, and the name the
/// setup screens push to become the app's root
/// (`pushNamedAndRemoveUntil('/home', (_) => false)`).
const String kLibraryRouteName = '/home';

/// Whether the route named [name] — or the navigator's first route — is where
/// "return to the library" must stop.
///
/// [isFirst] is the floor rather than a preference: it is what keeps the
/// unwinding total on a chain that has no named library route (a TV receiver or
/// a setup screen as the root, say). In the app as it stands the two clauses
/// name the same route — `/home` IS the first route — and the name is what keeps
/// that true if anything is ever pushed below it.
bool isLibraryLanding({required String? name, required bool isFirst}) =>
    name == kLibraryRouteName || isFirst;

/// [isLibraryLanding] in the shape `Navigator.popUntil` wants, so the call site
/// and the test drive the same predicate.
///
/// Player routes are anonymous (`_go` passes no `settings`), which is fine: only
/// the landing place has to be identifiable.
bool isLibraryLandingRoute(Route<dynamic> route) =>
    isLibraryLanding(name: route.settings.name, isFirst: route.isFirst);

/// Leaves the player for the library in ONE animated step — the step `Back`
/// plays — whatever the chain between them is.
///
/// [below] is the route directly under the player (the player's own
/// `didChangePrevious`, i.e. `PosterQuietRoute.previousRoute`), and anything
/// between it and the landing place is taken out of the chain WITHOUT animation
/// before the player pops.
///
/// `popUntil` alone animates every route it pops, and with a video opened from
/// the search screen the chain is `library → search → player`: popping both
/// played a three-page composite that matched neither `Back` (one page leaving)
/// nor a jump, so the same user action looked different depending on which
/// screen the video had been opened from. Taking the ones in between out is what
/// `popUntil` would do to them anyway — this only stops the user from watching
/// it, which is the difference between "Home" and "everything slides away at
/// once".
///
/// Only the route directly below the player is known (a route is told its own
/// neighbours), and that is enough: `search_screen` is the only screen that
/// opens a player without being the library, so the chain is at most
/// `library → search → player`. A deeper chain still finishes — `popUntil`
/// unwinds the rest — it just animates the extra levels, as it always did.
void leavePlayerForLibrary(
  NavigatorState navigator, {
  required Route<dynamic>? below,
}) {
  // `isActive` covers a route that is already gone: the announcement that put it
  // here can be one frame older than a removal, and `removeRoute` asserts.
  if (below != null && below.isActive && !isLibraryLandingRoute(below)) {
    navigator.removeRoute(below);
  }
  navigator.popUntil(isLibraryLandingRoute);
}
