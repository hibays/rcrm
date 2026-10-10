// utils/wheel_guard.dart
// One mouse wheel over the player, one handler.
//
// A wheel notch is a `PointerSignalEvent`, and Flutter arbitrates those through
// `PointerSignalResolver`: whoever is hit FIRST registers, and the first
// registrant wins. But the resolver only arbitrates between REGISTRANTS, and it
// does not resolve until the entire hit-test path has been dispatched — so a
// `Listener.onPointerSignal` that acts directly never takes part in it, and no
// `Scrollable` can stop it. That is exactly how a wheel over the playlist used
// to scroll the list AND step the player's volume in the same notch.
//
// `WheelGuard` fixes it by construction: it registers instead of acting, so a
// `Scrollable` hit nearer the pointer (the playlist) claims the notch and the
// action never runs; and it additionally asks the screen whether a panel owns
// the screen before acting, which covers the case the resolver cannot — a
// `Scrollable` only registers when the notch would really move it, so a wheel
// over a playlist already scrolled to its end registers nothing and would
// otherwise fall straight through to the player.

import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart' show HardwareKeyboard;
import 'package:flutter/widgets.dart';

/// The wheel delta the player should act on, or 0 for "not this one": a
/// horizontal-only scroll, a Ctrl+wheel (the platform's zoom gesture, never a
/// player gesture — the player has no zoom to offer), anything that is not a
/// plain mouse wheel, or any notch while a panel owns the screen.
double wheelGuardDeltaOrZero(
  PointerSignalEvent event, {
  required bool panelOpen,
}) {
  if (event is! PointerScrollEvent) return 0;
  if (HardwareKeyboard.instance.isControlPressed) return 0;
  final dy = event.scrollDelta.dy;
  if (dy == 0) return 0;
  // The wheel is the player's own gesture, so an open panel — which owns the
  // screen — takes it away from the player entirely rather than sharing it.
  if (panelOpen) return 0;
  return dy;
}

/// Routes mouse-wheel notches to [action] under two rules, both needed:
///
/// 1. `PointerSignalResolver` arbitration — a scrollable hit nearer the pointer
///    (an open playlist's `ListView`) wins, and [action] never runs.
/// 2. [gate] — the "a panel owns the screen" rule, read when the notch is
///    dispatched. The resolver alone is not enough: a `Scrollable` that cannot
///    move registers nothing, and the notch would then reach the player and
///    change the volume while the playlist is open.
///
/// [action] returns the delta it consumed (0 for a no-op, e.g. volume already at
/// its limit), which is what decides whether the event is answered: a notch the
/// player really used is consumed so nothing else can also act on it, and a
/// no-op knob stays silent exactly as it did before this guard existed.
class WheelGuard extends StatelessWidget {
  const WheelGuard({
    super.key,
    required this.action,
    required this.gate,
    this.child,
  });

  /// Applies the wheel delta; returns the delta it consumed.
  final double Function(double delta) action;

  /// The "a panel owns the screen" rule, read when the notch is dispatched.
  final bool Function() gate;

  final Widget? child;

  @override
  Widget build(BuildContext context) {
    return Listener(
      behavior: HitTestBehavior.opaque,
      onPointerSignal: (event) {
        if (event is! PointerScrollEvent) return;
        // Register even when a panel is open: the first registrant wins, so
        // claiming the notch here is what keeps it away from the player
        // underneath — a panel owns the screen, so no other layer may answer
        // for it either (the callback then does nothing).
        GestureBinding.instance.pointerSignalResolver.register(event, (ev) {
          final delta = wheelGuardDeltaOrZero(ev, panelOpen: gate());
          if (delta == 0) return;
          if (action(delta) != 0) {
            ev.respond(allowPlatformDefault: false);
          }
        });
      },
      child: child,
    );
  }
}

/// The player's wheel layer: `WheelGuard` wired to [setVolume], so the wheel
/// decision is the same one the screen makes and can be driven in a test
/// without a `Player` (the screen itself cannot: it owns a media_kit `Player`).
///
/// [nextVolume] is the caller's arithmetic — how far one notch moves the volume,
/// and whether it may move at all — evaluated against the current value; this
/// layer applies the result through [setVolume] and reports whether anything
/// moved.
class PlayerWheelLayer extends StatelessWidget {
  const PlayerWheelLayer({
    super.key,
    required this.volume,
    required this.nextVolume,
    required this.setVolume,
    required this.gate,
    this.child,
  });

  /// The current volume, read at dispatch time.
  final double Function() volume;

  /// The volume one wheel delta would produce, or [volume] unchanged for a
  /// no-op (a notch at the limit).
  final double Function(double current, double delta) nextVolume;

  final ValueChanged<double> setVolume;

  /// The "a panel owns the screen" rule.
  final bool Function() gate;

  final Widget? child;

  @override
  Widget build(BuildContext context) {
    return WheelGuard(
      gate: gate,
      action: (delta) {
        final current = volume();
        final next = nextVolume(current, delta);
        // Nothing to do: report no-op, so the notch is neither consumed nor
        // announced as the player's.
        if (next == current) return 0;
        setVolume(next);
        return delta;
      },
      child: child,
    );
  }
}
