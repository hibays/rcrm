// utils/viewer_gesture.dart
// ONE owner for the touch sequence on a photo page.
//
// The viewer has three things that can consume a drag:
//   * the pager, on a sideways drag;
//   * the pull-to-dismiss, on a downward drag at 1x;
//   * zoom/pan, on two fingers (or one finger on an already zoomed picture).
//
// They used to be three separate pieces of state — a raw pointer Listener for
// the pull, a ScaleGestureRecognizer for the pager and the pinch, and a
// `_isZoomed` bool in between — so a gesture could be claimed by two of them
// at once. This file is the one state tree they all feed, with the priority
// order written down and tested:
//
//   zoom (multi-touch / already zoomed)  >  page or pull (axis lock)  >  idle
//
// The owner of a sequence is decided once and never re-decided: a finger that
// curves, a second finger, or a change of direction cannot hand the gesture to
// somebody else. The one transition that is allowed is the pull standing down
// when zoom takes over, because a pinch is a superset of a pull (two fingers
// on a picture always mean zoom) and a pull that kept translating would move
// the photo twice.
//
// This is a pure value type: the page owns one instance, and every transition
// returns the next instance. No Flutter state, no animation, no geometry.

import 'dart:ui' show Offset;

import 'package:flutter/foundation.dart' show immutable;

/// Who owns the touch sequence in flight.
enum ViewerGestureOwner {
  /// No sequence has started (or the last one was finished).
  idle,

  /// A pointer is down but has not travelled far enough to commit.
  undecided,

  /// The pager owns it: a sideways drag.
  page,

  /// The pull-to-dismiss owns it: a downward drag at 1x.
  pull,

  /// Zoom/pan owns it: two or more fingers were down at once, or the picture
  /// was already zoomed when the sequence began.
  zoom,
}

/// Travel before the direction lock commits to an axis, in logical pixels.
const double viewerAxisLockSlop = 8;

/// How far the leading axis must beat the other one to own the gesture.
const double viewerAxisDominance = 1.5;

/// Which owner a single-pointer sequence commits to at [travel] from where it
/// went down, or null while it is still undecided.
///
/// [pullAllowed] is the viewer's own rule ([pullAllowed] in
/// `widgets/viewer_zoom.dart`): a zoomed picture or a playing live photo owns
/// the drag. Losing the pull never takes the pager with it — a sideways drag
/// still turns the page.
ViewerGestureOwner? decideViewerGestureOwner(
  Offset travel, {
  required bool pullAllowed,
}) {
  final dx = travel.dx.abs();
  final dy = travel.dy.abs();
  // Sideways clearly dominates: the pager owns the gesture, so the pull must
  // contribute nothing at all for the rest of it.
  if (dx > viewerAxisLockSlop && dx > dy * viewerAxisDominance) {
    return ViewerGestureOwner.page;
  }
  if (!pullAllowed) return null;
  // Downward travel that dominates: the pull, on the rule it always used to
  // engage (8px down, and not more than 1.5x sideways).
  if (travel.dy >= viewerAxisLockSlop &&
      dx <= travel.dy * viewerAxisDominance) {
    return ViewerGestureOwner.pull;
  }
  return null;
}

/// Immutable state of one touch sequence on one photo page.
///
/// A sequence starts when the first pointer goes down and is over when the last
/// one lifts, but the [owner] survives the last lift: the scale recognizer's
/// end is delivered AFTER the pointer Listener's up, and it still needs to know
/// whether the sequence that just ended was a pull (settle the pager behind it)
/// or a pinch (settle a page drag it interrupted). The next [pointerDown]
/// starts a fresh sequence and replaces that lingering owner.
@immutable
class ViewerGesture {
  const ViewerGesture({
    this.pointers = const <int>{},
    this.owner = ViewerGestureOwner.idle,
  });

  /// The state before any pointer has touched the page.
  static const ViewerGesture idle = ViewerGesture();

  /// Pointer ids currently down. A sequence with no pointers is over (its
  /// owner is the record of how it ended).
  final Set<int> pointers;

  /// Who owns (or owned) the sequence.
  final ViewerGestureOwner owner;

  /// True while at least one finger is down.
  bool get isActive => pointers.isNotEmpty;

  bool get pullOwnsGesture => owner == ViewerGestureOwner.pull;

  bool get zoomOwnsGesture => owner == ViewerGestureOwner.zoom;

  /// The scale recognizer reports a second finger before this sequence has
  /// seen one (e.g. a pointer down that landed outside the page's Listener).
  /// Promotes the sequence to zoom without pretending a pointer arrived.
  ViewerGesture zoomNow() => owner == ViewerGestureOwner.zoom
      ? this
      : ViewerGesture(pointers: pointers, owner: ViewerGestureOwner.zoom);

  /// First pointer of a sequence: undecided, or already zoom when the picture
  /// is zoomed ([zoomed]) because that finger means pan, never pull.
  ///
  /// Any pointer arriving while one is already down makes the sequence a pinch
  /// for the rest of its life — this is the transition that stops a two-finger
  /// zoom from also pulling the photo down.
  ViewerGesture pointerDown(int pointer, {bool zoomed = false}) {
    if (pointers.contains(pointer)) return this;
    final next = <int>{...pointers, pointer};
    if (pointers.isNotEmpty) {
      return ViewerGesture(pointers: next, owner: ViewerGestureOwner.zoom);
    }
    return ViewerGesture(
      pointers: next,
      owner: zoomed ? ViewerGestureOwner.zoom : ViewerGestureOwner.undecided,
    );
  }

  /// Commits an undecided single-pointer sequence by [travel] from where it
  /// went down. A decided sequence — and any multi-touch one — keeps its
  /// owner; that is what makes a curving finger unable to switch lanes.
  ViewerGesture pointerMove(Offset travel, {required bool pullAllowed}) {
    if (pointers.length != 1 || owner != ViewerGestureOwner.undecided) {
      return this;
    }
    final decided = decideViewerGestureOwner(travel, pullAllowed: pullAllowed);
    if (decided == null) return this;
    return ViewerGesture(pointers: pointers, owner: decided);
  }

  /// Removes a lifted pointer. The last lift leaves [owner] in place so the
  /// scale end can read how the sequence ended; [finish] clears it once that
  /// has been handled. Lifting one finger of a pinch keeps the sequence zoomed
  /// — the remaining finger must not turn into a pull.
  ViewerGesture pointerUp(int pointer) {
    if (!pointers.contains(pointer)) return this;
    final next = <int>{...pointers}..remove(pointer);
    return ViewerGesture(pointers: next, owner: owner);
  }

  /// Ends the sequence completely. Called when the scale recognizer's end has
  /// been handled (or the page is going away).
  ViewerGesture finish() => idle;

  @override
  bool operator ==(Object other) =>
      other is ViewerGesture &&
      other.owner == owner &&
      other.pointers.length == pointers.length &&
      other.pointers.containsAll(pointers);

  @override
  int get hashCode => Object.hash(owner, Object.hashAllUnordered(pointers));

  @override
  String toString() =>
      'ViewerGesture(owner: ${owner.name}, pointers: $pointers)';
}
