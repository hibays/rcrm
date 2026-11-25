// widgets/smart_popup_menu.dart
// A drop-in replacement for [PopupMenuButton] built on
// `flutter_smart_dialog`'s anchored [SmartDialog.showAttach].
//
// Why not keep PopupMenuButton: the project is migrating every transient
// surface (dialogs, snackbars, menus) onto flutter_smart_dialog so they all
// share one overlay/lifecycle. showAttach anchors the menu to the trigger
// widget and reuses the same mask/back-button handling as the dialogs.
//
// Behaviour mirrors the native control:
//  - tap the [child] trigger to open;
//  - the menu opens down from the trigger's bottom-left (like the default
//    PopupMenuButton) unless [openUpward] is set, which flips it to open up;
//  - tap an item -> [SmartDialog.dismiss(result: value)] -> [onSelected];
//  - tap outside / back -> [onClosed] (the native `onCanceled` equivalent);
//  - [onOpened] fires the moment the menu is asked to open.
//
// GEOMETRY is the native control's too, and that part is not cosmetic: the
// anchor sizes the panel from its content, so an unconstrained menu stretches
// to the screen (measured on Windows: the player's speed menu covered the
// whole window width). PopupMenuButton's own model is reproduced here — loose
// 112..280dp by default, an intrinsic-width body in 56dp steps, 8dp of menu
// padding, and 48dp rows, because a menu is a list of choices, not a panel.
//
// Items are [SmartPopupMenuItem] widgets (not plain data) so tests can find a
// row by type exactly as they used to find `PopupMenuItem<T>`; each one's
// [SmartPopupMenuItem.child] is the full row content (check mark, icon, label,
// trailing — whatever the caller wants), so the player's custom accent-coloured
// rows are reproduced exactly rather than forced through a one-shape ListTile.

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';

/// One selectable entry in a [SmartPopupMenu].
///
/// [child] is the entire row contents — build it exactly as you would the
/// `child` of a `PopupMenuItem` (a `Row` with a leading icon, label, optional
/// trailing check, etc.). [SmartPopupMenu] only wraps it in a tappable, padded
/// surface; it never inspects or re-lays-out the content.
class SmartPopupMenuItem<T> extends StatelessWidget {
  final T value;
  final Widget child;
  final bool enabled;

  /// Row padding. Horizontal 12dp mirrors Material 3's own menu item inset;
  /// the vertical 6dp is this row's own air, because Material gives a menu item
  /// NO vertical padding and a row that grows past the floor would otherwise
  /// touch the next label.
  final EdgeInsetsGeometry padding;

  /// The row's floor. 48dp is one menu row (Material's minimum interactive
  /// dimension), and it is a FLOOR: content that outgrows it grows the row.
  final double minHeight;

  const SmartPopupMenuItem({
    super.key,
    required this.value,
    required this.child,
    this.enabled = true,
    this.padding = const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
    this.minHeight = 48,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: enabled
          ? () {
              // The page reacts NOW; the panel animates out behind it. Routing
              // the choice through `showAttach`'s future meant it arrived only
              // after the exit animation, which reads as "the menu has to be
              // gone before the filter applies".
              final pick = _MenuPickScope.maybeOf(context);
              SmartDialog.dismiss(
                status: SmartStatus.attach,
                tag: pick?.tag,
                result: value,
              );
              pick?.onPick(value);
            }
          : null,
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: minHeight),
        child: Padding(
          padding: padding,
          child: Align(
            alignment: AlignmentDirectional.centerStart,
            heightFactor: 1.0,
            child: child,
          ),
        ),
      ),
    );
  }
}

/// Carries the "deliver this choice now" callback down to [SmartPopupMenuItem].
///
/// A menu item has no idea whether its owner wants the value immediately (a
/// filter that should apply on the click) or only as the menu's result (the
/// point-anchored [showSmartMenu], whose caller awaits it), so the decision
/// belongs to the panel that built the rows.
class _MenuPickScope extends InheritedWidget {
  final ValueChanged<Object?> onPick;

  /// The tag of the attach panel this row belongs to, so dismissing a row
  /// never dismisses a visible notify instead (smart_dialog checks notify
  /// first). Null only for a bare row outside a panel.
  final String? tag;

  const _MenuPickScope({
    required this.onPick,
    this.tag,
    required super.child,
  });

  static _MenuPickScope? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<_MenuPickScope>();

  @override
  bool updateShouldNotify(_MenuPickScope oldWidget) =>
      onPick != oldWidget.onPick || tag != oldWidget.tag;
}

class SmartPopupMenu<T> extends StatelessWidget {
  /// The trigger shown in the parent layout. For an icon-only menu pass an
  /// `Icon`; for the old `child:` (chip) form pass that same widget. It is
  /// wrapped in a tappable ink surface and, when [tooltip] is set, a tooltip.
  final Widget child;

  final List<SmartPopupMenuItem<T>> items;

  final ValueChanged<T>? onSelected;

  /// Mirrors `PopupMenuButton.onOpened`.
  final VoidCallback? onOpened;

  /// Mirrors `PopupMenuButton.onCanceled` — fires whenever the menu closes
  /// without a selection (outside tap, back button, mask).
  final VoidCallback? onClosed;

  /// Open upward from the trigger's top-left instead of downward. Used by the
  /// player controls whose menus must clear the transport bar.
  final bool openUpward;

  /// Anchor the menu to the trigger's RIGHT edge instead of its left. For a
  /// right-edge trigger (the toolbar's overflow button), a left-anchored menu
  /// would grow off-screen; the attach layer clamps it, but the result reads
  /// as a menu that fell away from its button. Right anchoring keeps it under
  /// the button it belongs to.
  final bool anchorRight;

  final String? tooltip;

  /// Surface colour of the menu panel. Defaults to the app's ash panel; the
  /// player passes its own `playerSurface`.
  final Color? backgroundColor;

  final double elevation;
  final BorderRadius? borderRadius;

  /// Width constraints for the whole menu. Null means PopupMenuButton's own
  /// default: loose 112..280dp around the content's intrinsic width.
  final BoxConstraints? constraints;

  const SmartPopupMenu({
    super.key,
    required this.child,
    required this.items,
    this.onSelected,
    this.onOpened,
    this.onClosed,
    this.openUpward = false,
    this.anchorRight = false,
    this.tooltip,
    this.backgroundColor,
    this.elevation = 6,
    this.borderRadius,
    this.constraints,
  });

  /// Material 3's own popup-menu shape (4dp). A caller that wants the app's
  /// card radius (the player's menus do) passes [RCrmRadii.md] itself.
  static const BorderRadius _nativeMenuRadius = BorderRadius.all(
    Radius.circular(4),
  );

  @override
  Widget build(BuildContext context) {
    final trigger = InkWell(
      onTap: () => _open(context),
      borderRadius: borderRadius ?? _nativeMenuRadius,
      child: child,
    );
    return tooltip != null
        ? Tooltip(message: tooltip!, child: trigger)
        : trigger;
  }

  Future<void> _open(BuildContext context) async {
    onOpened?.call();
    var delivered = false;
    // A unique tag keeps this panel's dismiss from ever taking a visible
    // notify down with it: SmartDialog checks the notify queue BEFORE the
    // dialog queue, so an untagged dismiss while a "copied" toast is up eats
    // the toast instead of the menu and the row's action never runs.
    final tag = 'menu-${Object().hashCode}';
    final result = await SmartDialog.showAttach<T>(
      tag: tag,
      // The trigger's own context is the anchor.
      targetContext: context,
      // bottomLeft = open downward, left-aligned (native default);
      // topLeft + inside = open upward, left-aligned (player bars);
      // the Right variants keep a right-edge trigger's menu on screen beside
      // its button instead of letting it grow off the edge and get clamped.
      alignment: anchorRight
          ? (openUpward ? Alignment.topRight : Alignment.bottomRight)
          : (openUpward ? Alignment.topLeft : Alignment.bottomLeft),
      // A menu has no dark scrim — the transparent mask still captures the
      // outside tap so it dismisses, but the page beneath stays visible.
      maskColor: Colors.transparent,
      clickMaskDismiss: true,
      onDismiss: onClosed,
      builder: (_) => _SmartMenuPanel<T>(
        items: items,
        backgroundColor: backgroundColor,
        elevation: elevation,
        borderRadius: borderRadius ?? _nativeMenuRadius,
        constraints: constraints,
        tag: tag,
        // A row tap delivers its value itself, one frame after the click.
        // `delivered` is also the one-shot LATCH, not just a note that the
        // future is redundant: the panel stays on screen and hit-testable
        // through its exit animation (measured: the rows are still there a
        // frame after the tap), so a second tap on the same row would deliver
        // the same choice twice. That is not harmless — re-picking the active
        // sort field flips the direction (see `_SortNotifier.set`), so two
        // deliveries would flip and flip back while writing both.
        onPick: (value) {
          if (delivered) return;
          delivered = true;
          onSelected?.call(value as T);
        },
      ),
    );
    // Only the paths that produce a result WITHOUT a row tap get here (and any
    // future one); the guard keeps a choice from being delivered twice.
    if (result != null && !delivered) onSelected?.call(result);
  }
}

/// Opens a menu at a GLOBAL point — the same panel, rows, geometry and dismiss
/// rules as [SmartPopupMenu], for a surface that has no trigger widget of its
/// own: an item's long-press or right-click.
///
/// The anchor is a position, not a widget, so the menu belongs to the POINT the
/// user pressed rather than to a card that a scroll can move out from under it.
/// [openUpward] is the caller's decision because only it knows how many rows the
/// menu will have before that menu is measured (`utils/menu_placement.dart`
/// owns the arithmetic).
///
/// Returns the chosen value, or null when the menu was dismissed.
Future<T?> showSmartMenu<T>({
  required Offset anchor,
  required List<SmartPopupMenuItem<T>> items,
  required bool openUpward,
  Color? backgroundColor,
  double elevation = 6,
  BorderRadius? borderRadius,
  BoxConstraints? constraints,
  VoidCallback? onClosed,
}) {
  final tag = 'menu-${Object().hashCode}';
  return SmartDialog.showAttach<T>(
    tag: tag,
    // No targetContext: the point is the target, and passing the card's context
    // as well would make AttachWidget offset the menu by that card's height.
    targetContext: null,
    // The callback ignores the context's own offset and answers with the global
    // point, so the menu lands where the finger or pointer was.
    targetBuilder: (_, _) => anchor,
    // bottomLeft = the menu's top-left starts at the point (downward);
    // topLeft = its bottom-left ends at the point (upward).
    alignment: openUpward ? Alignment.topLeft : Alignment.bottomLeft,
    maskColor: Colors.transparent,
    clickMaskDismiss: true,
    onDismiss: onClosed,
    builder: (_) => _SmartMenuPanel<T>(
      items: items,
      backgroundColor: backgroundColor,
      elevation: elevation,
      borderRadius: borderRadius ?? SmartPopupMenu._nativeMenuRadius,
      constraints: constraints,
      tag: tag,
    ),
  );
}

/// The panel itself, shared by the trigger-based menu and the point-based one.
class _SmartMenuPanel<T> extends StatelessWidget {
  final List<SmartPopupMenuItem<T>> items;
  final Color? backgroundColor;
  final double elevation;
  final BorderRadius borderRadius;
  final BoxConstraints? constraints;

  /// The tag of the surrounding attach dialog. A row tap dismisses by tag so
  /// a visible notify is never dismissed first.
  final String tag;

  /// Called with the chosen row's value the instant it is tapped. Null for the
  /// point-anchored menu, whose caller consumes the dialog's result instead.
  final ValueChanged<Object?>? onPick;

  const _SmartMenuPanel({
    required this.items,
    required this.backgroundColor,
    required this.elevation,
    required this.borderRadius,
    required this.constraints,
    required this.tag,
    this.onPick,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final rows = Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [...items],
    );
    final panel = Material(
      // A menu is a card, and Material 3's own menu paints it with the surface
      // tint DISABLED. Say so explicitly: the player's surface is a fixed Ash,
      // and a future non-transparent tint default would wash it toward the
      // theme's primary.
      type: MaterialType.card,
      color: backgroundColor ?? RCrmColors.ash,
      surfaceTintColor: Colors.transparent,
      elevation: elevation,
      borderRadius: borderRadius,
      clipBehavior: Clip.antiAlias,
      // PopupMenuItem painted its rows with the theme's `labelLarge` and the
      // palette's `onSurface` ink. Keep that baseline: a caller that styles
      // only its own values (the toolbar's plain labels) still looks like a
      // menu row rather than like body copy.
      textStyle: theme.textTheme.labelLarge,
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: _MenuPickScope(
          onPick: onPick ?? (_) {},
          tag: tag,
          child: rows,
        ),
      ),
    );
    // IntrinsicWidth is what keeps a menu a menu: the anchored surface would
    // otherwise hand the Column the whole screen width, and `stretch` would
    // fill it (measured: the player's speed menu opened as a full-window slab).
    //
    // Height needs a cap too. The toolbar's overflow menu can carry every
    // extension in a library plus the other controls — 19 rows measured — and
    // an unbounded panel puts the last rows below the screen, unreachable. A
    // bounded height makes the SingleChildScrollView above actually scroll;
    // short menus (the player's, the old 3-row Organize menu) keep their
    // natural size because this is a cap, not a fixed height. The 96dp leaves
    // room for the trigger and the system bars on either anchor direction.
    return ConstrainedBox(
      constraints:
          (constraints ?? const BoxConstraints(minWidth: 112, maxWidth: 280))
              .copyWith(maxHeight: MediaQuery.sizeOf(context).height - 96),
      child: IntrinsicWidth(stepWidth: 56, child: panel),
    );
  }
}
