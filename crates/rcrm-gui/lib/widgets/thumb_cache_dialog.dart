// widgets/thumb_cache_dialog.dart
// The thumbnail cache's one entry point, opened: the grading, made legible and
// made the user's to decide.
//
// Two things this dialog is deliberately NOT:
//
//   * It is not a pair of buttons that do something to the user's cache. The
//     three tiers are ENTRIES THEY CAN TAP, each showing what it holds and how
//     old that is ("4.2 MB · generated 2 months ago" — an age, not a date: a
//     boundary answers "how old is this?", and a calendar date makes the reader
//     subtract). Ticking a tier is what allows it to be spent.
//   * It is not a policy applied silently. Unticking a tier the automatic plan
//     would have touched keeps it, even when that leaves the cache over budget —
//     their call, and the reason the selection goes to the rule rather than being
//     filtered afterwards.
//
// [plan] may be a `Future` (what the settings row passes) or a ready value (what
// a test passes). Either way the ACTIONS are usable immediately: the dialog is
// opened by a tap, and reading a cache directory is disk work that must not be
// able to hold a tap hostage — and in a widget test it cannot complete at all,
// which is what made an awaiting version of this dialog untestable.

import 'dart:async';

import 'package:flutter/material.dart';

import '../services/thumb_cache.dart';
import '../utils/thumb_cache_policy.dart';

/// What the user chose. Null (the dialog was dismissed) means nothing runs.
///
/// [limitMb] is the size Auto trim trims to — chosen HERE, in the flow, rather
/// than as a settings row of its own: it is part of deciding how to clean the
/// cache, not a separate policy the user has to go and find. `0` means the
/// platform's default budget.
typedef ThumbCacheChoice = ({
  bool clearAll,

  /// True when the choice is "delete the tiers in [spend] WHOLE" (a row's own
  /// delete); false for the default strategy, which stops at the budget.
  bool wholeTier,
  Set<ThumbCacheTier> spend,
  int limitMb,
});

class ThumbCacheDialog extends StatefulWidget {
  /// The grading to show — `ThumbCache.preview()`, or a plan already in hand.
  final FutureOr<ThumbCachePlan> plan;

  /// The target the last Auto trim used (`ThumbCache.limitMb`), so the choice is
  /// remembered without being a setting the user has to go and find.
  final int initialLimitMb;

  /// `now` is injectable so a test can pin the ages the rows print.
  final DateTime Function() clock;

  const ThumbCacheDialog({
    super.key,
    required this.plan,
    this.initialLimitMb = 0,
    this.clock = DateTime.now,
  });

  @override
  State<ThumbCacheDialog> createState() => _ThumbCacheDialogState();
}

class _ThumbCacheDialogState extends State<ThumbCacheDialog> {
  ThumbCachePlan? _plan;

  /// The size the default clean-up trims to, seeded from the remembered setting
  /// and switchable at the point of use — the control that makes the strategy the
  /// user's rather than a black box.
  late int _limitMb = widget.initialLimitMb;

  @override
  void initState() {
    super.initState();
    Future.value(widget.plan).then((plan) {
      if (!mounted) return;
      setState(() => _plan = plan);
    }, onError: (_) {});
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final plan = _plan;
    final now = widget.clock();
    final nothing = plan != null && plan.graded == 0;

    // A themed Dialog rather than a stock SimpleDialog, for three reasons that are
    // all defects rather than taste: the system's corner radius is 8px and not the
    // Material default, the body must SCROLL (five rows plus two actions do not
    // fit a phone in landscape, and an overflow stripe is not a state), and the
    // heading needs the system's own type role instead of the dialog's built-in.
    //
    // Everything below comes from `Theme.of(context)` — no hex repeated here — so
    // this screen moves with the palette in DESIGN.md rather than beside it.
    return Dialog(
      backgroundColor: scheme.surface,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      clipBehavior: Clip.antiAlias,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 420),
        child: SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.only(top: 20, bottom: 8),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 0, 24, 6),
                  child: Text(
                    'Thumbnail cache',
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 0, 24, 12),
                  child: Text(
                    plan == null
                        ? 'Reading the cache…'
                        : nothing
                        ? 'Nothing cached yet.'
                        : 'Each row deletes its own tier, whole. Auto trim is the '
                              'default strategy: coldest first, down to the size '
                              'below.',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: scheme.onSurfaceVariant,
                    ),
                  ),
                ),
                if (plan != null && !nothing)
                  for (final tier in ThumbCacheTier.values.reversed)
                    _tierTile(plan, tier, now),
                const SizedBox(height: 8),
                // The strategy, at the point of use: what Auto trim will do, and the
                // one number it depends on. A policy the user can neither read nor
                // move is not a policy they chose.
                if (!nothing)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(24, 0, 16, 4),
                    child: Row(
                      children: [
                        Expanded(
                          child: Text(
                            'Trim to',
                            style: theme.textTheme.bodyMedium,
                          ),
                        ),
                        DropdownButton<int>(
                          value: _limitMb,
                          borderRadius: BorderRadius.circular(8),
                          underline: const SizedBox.shrink(),
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: scheme.primary,
                            fontWeight: FontWeight.w600,
                          ),
                          onChanged: (v) {
                            if (v != null) setState(() => _limitMb = v);
                          },
                          items: [
                            for (final mb in kThumbCacheLimitChoices)
                              DropdownMenuItem(
                                value: mb,
                                child: Text(thumbCacheLimitLabel(mb)),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                const SizedBox(height: 8),
                // No size target here: it could only veto the ticks the user just
                // made, which is what "Auto trim deletes what I ticked" rules out.
                // The budget still exists in the policy for a size-targeted
                // clean-up; this dialog is not one.
                // Disabled when the cache is EMPTY, not merely when it is small: a
                // control that can only do nothing is the dead-control defect, and
                // "Auto trim" on an empty cache is exactly that. While the plan is
                // still being read it stays enabled — `manage` re-reads the cache
                // anyway, so an early tap is honest work, not a lie.
                SimpleDialogOption(
                  onPressed: nothing
                      ? null
                      : () => Navigator.pop(context, (
                          clearAll: false,
                          wholeTier: false,
                          spend: kAllThumbCacheTiers,
                          limitMb: _limitMb,
                        )),
                  child: _Option(
                    icon: const Icon(Icons.auto_delete),
                    title: 'Auto trim',
                    detail:
                        'Removes the coldest entries first and stops at the size '
                        'below. Nothing else is touched.',
                    dimmed: nothing,
                  ),
                ),
                SimpleDialogOption(
                  onPressed: nothing
                      ? null
                      : () => Navigator.pop(context, (
                          clearAll: true,
                          wholeTier: false,
                          spend: const <ThumbCacheTier>{},
                          limitMb: _limitMb,
                        )),
                  child: _Option(
                    icon: Icon(Icons.delete_sweep),
                    title: 'Delete all',
                    detail:
                        'Every cached thumbnail goes; they are regenerated as '
                        'you browse.',
                    danger: true,
                    dimmed: nothing,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _tierTile(ThumbCachePlan plan, ThumbCacheTier tier, DateTime now) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    // ONE switch for one tier. The label, its bytes, when it was generated and when
    // it was last opened all belong to the same question; reading them out in two
    // switches was two places to forget a tier in.
    final (label, bytes, upTo, used) = switch (tier) {
      ThumbCacheTier.cold => (
        'Cold',
        plan.coldBytes,
        plan.coldUpTo,
        plan.coldUsedAt,
      ),
      ThumbCacheTier.warm => (
        'Warm',
        plan.warmBytes,
        plan.warmUpTo,
        plan.warmUsedAt,
      ),
      // The newest tier has no cut of its own: it runs to now.
      ThumbCacheTier.fresh => (
        'Fresh',
        plan.freshBytes,
        null,
        plan.freshUsedAt,
      ),
    };
    final age = upTo == null
        ? 'newest — what you are looking at'
        : 'generated ${describeAge(upTo, now: now)}';
    // The second axis, shown only when there is something to say: a tier nothing
    // has ever read says only when it was generated, and inventing "never opened"
    // for a cache that simply predates the access log would be a claim we cannot
    // support.
    final usedLine = used == null
        ? ''
        : ' · opened ${describeAge(used, now: now)}';
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 20),
      title: Text(
        label,
        style: theme.textTheme.titleSmall?.copyWith(
          color: scheme.onSurface,
          fontWeight: FontWeight.w600,
        ),
      ),
      subtitle: Text(
        '${ThumbCache.human(bytes)} · $age$usedLine',
        style: theme.textTheme.bodySmall?.copyWith(
          color: scheme.onSurfaceVariant,
        ),
      ),
      // The row's OWN delete: one tap removes this tier and nothing else — the
      // manual per-tier removal, with no selection model in between. Expressed as
      // "spend only this tier, drop it whole", which is what that means.
      trailing: IconButton(
        icon: const Icon(Icons.delete_outline),
        tooltip: 'Delete the $label tier',
        color: scheme.error,
        onPressed: () => Navigator.pop(context, (
          clearAll: false,
          wholeTier: true,
          spend: {tier},
          limitMb: _limitMb,
        )),
      ),
    );
  }
}

/// One action in the dialog: an icon, what it does, and what it costs.
class _Option extends StatelessWidget {
  /// A WIDGET, not an `IconData` — the shape the release icon tree-shaker can see.
  /// An icon handed around as a value is invisible to it (measured on this app:
  /// `Icon(groupingIcon(key))` and `_Option(icon: Icons.auto_delete)` both shipped
  /// as empty glyphs while `const Icon(Icons.folder)` in the same tree rendered).
  final Widget icon;
  final String title;
  final String detail;

  /// Dimmed when the action cannot run (an empty cache): a `SimpleDialogOption`
  /// with a null `onPressed` dims only the text Material draws itself, and this
  /// row is custom, so the icon and chip would otherwise stay at full strength on
  /// a control that does nothing.
  final bool dimmed;

  /// Destructive actions take the design system's error token — the palette's red,
  /// not one invented here — so the one button that throws everything away reads
  /// as the one button that throws everything away.
  final bool danger;

  const _Option({
    required this.icon,
    required this.title,
    required this.detail,
    this.dimmed = false,
    this.danger = false,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final accent = danger ? scheme.error : scheme.primary;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // The chip, restored: it gives the two actions equal optical weight and
        // carries the accent into a row that has no other chrome. It had been lost
        // — which is why the actions showed no chip at all, not merely no glyph.
        Container(
          width: 32,
          height: 32,
          decoration: BoxDecoration(
            color: accent.withValues(alpha: dimmed ? 0.06 : 0.14),
            borderRadius: BorderRadius.circular(8),
          ),
          // The colour goes through IconTheme so the icon itself can stay a plain
          // literal at the call site, which is what the shaker needs to see.
          child: IconTheme.merge(
            data: IconThemeData(
              size: 18,
              color: dimmed ? scheme.onSurfaceVariant : accent,
            ),
            child: icon,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title,
                // The token red belongs to the ACTIVE destructive action, and only
                // to it: disabled, the title greys with its icon, so the row reads
                // as unavailable rather than as a live threat.
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  color: dimmed
                      ? scheme.onSurfaceVariant
                      : (danger ? scheme.error : null),
                ),
              ),
              const SizedBox(height: 2),
              Text(
                detail,
                style: TextStyle(color: Theme.of(context).hintColor),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
