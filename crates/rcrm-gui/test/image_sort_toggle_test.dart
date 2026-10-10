// test/image_sort_toggle_test.dart
// The image page's sort re-pick rule, at the seam it lives on.
//
// `SettingsNotifier.setImageSort` is where the image album view's sort is
// committed: re-picking the active field flips the direction, a different
// field starts ascending. Unlike the video page there is no image sort control
// yet — `setImageSort` has no widget caller, and the album view only consumes
// `imageSort` / `imageSortAsc` when it orders the grid — so this is a
// provider-level test rather than a full-screen widget test. It pins the
// provider contract the video page's `_SortNotifier.set` mirrors, plus the
// persistence the two sides now share.
//
// The rendered order itself is derived in `screens/image_screen.dart`
// (`_sortImages`, keyed on the field *and* the direction), which watches this
// state; that projection is not re-tested here.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/services/settings_service.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test(
    're-picking the active field flips the image sort direction and persists '
    'it, and a different field starts that field ascending',
    () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      final settings = container.read(uiSettingsProvider.notifier);

      expect(container.read(uiSettingsProvider).imageSort, 'name');
      expect(container.read(uiSettingsProvider).imageSortAsc, isTrue);

      // Re-pick the field already in effect: the field stays, the direction
      // flips.
      await settings.setImageSort('name');
      expect(container.read(uiSettingsProvider).imageSort, 'name');
      expect(container.read(uiSettingsProvider).imageSortAsc, isFalse);
      expect(
        await SettingsService().getImageSortAsc(),
        isFalse,
        reason: 'the flip must be persisted, not only held in memory',
      );

      // Relaunch: a fresh container plus the startup call app.dart makes.
      final relaunched = ProviderContainer();
      addTearDown(relaunched.dispose);
      await relaunched.read(uiSettingsProvider.notifier).load();
      expect(relaunched.read(uiSettingsProvider).imageSort, 'name');
      expect(relaunched.read(uiSettingsProvider).imageSortAsc, isFalse);

      // A different field: it becomes the field, and ascending is where it
      // starts — the same convention the video page settled on.
      await settings.setImageSort('date');
      expect(container.read(uiSettingsProvider).imageSort, 'date');
      expect(container.read(uiSettingsProvider).imageSortAsc, isTrue);
      expect(await SettingsService().getImageSort(), 'date');
      expect(await SettingsService().getImageSortAsc(), isTrue);

      // And a third re-pick flips that field's direction, so the rule is not
      // a one-way switch.
      await settings.setImageSort('date');
      expect(container.read(uiSettingsProvider).imageSort, 'date');
      expect(container.read(uiSettingsProvider).imageSortAsc, isFalse);
      expect(await SettingsService().getImageSortAsc(), isFalse);
    },
  );
}
