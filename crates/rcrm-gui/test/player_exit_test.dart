// test/player_exit_test.dart
// "Return to the library": the landing decision, and what `Navigator.popUntil`
// really does with it.
//
// The player screen cannot be mounted in a test (it creates a real media_kit
// `Player` in its first frame), so the decision lives in `utils/player_exit.dart`
// as a pure predicate and the navigator behaviour is driven here through a plain
// route chain with the names the app uses — `/home` is the only named route in
// the chain, every player route is anonymous (`_go` passes no settings).
//
// The two ways this could be wrong are both covered:
//
//  * landing on the WRONG route — the predicate must stop at `/home` even when
//    `/home` is not the navigator's first route, and
//  * landing on NO route — `popUntil` pops every route its predicate rejects, so
//    a predicate that matches nothing empties the navigator. The `isFirst` floor
//    is what makes it total, and the second widget test is that case.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/player_exit.dart';

/// Pushes an anonymous player route above whatever is on screen and returns the
/// navigator. `PopScope(canPop: false)` is deliberately part of it: that is what
/// the player screen wraps itself in, and `popUntil` must not be refused by it.
Future<NavigatorState> _pushPlayer(
  WidgetTester tester, {
  void Function(bool didPop)? onPopInvoked,
}) async {
  final nav = tester.state<NavigatorState>(find.byType(Navigator));
  nav.push(
    MaterialPageRoute<void>(
      builder: (_) => PopScope<void>(
        canPop: false,
        onPopInvokedWithResult: (didPop, _) => onPopInvoked?.call(didPop),
        child: const Text('player'),
      ),
    ),
  );
  await tester.pumpAndSettle();
  return nav;
}

void main() {
  group('isLibraryLanding', () {
    test('names the library route', () {
      expect(isLibraryLanding(name: kLibraryRouteName, isFirst: false), isTrue);
    });

    test('any other route is not the landing place', () {
      for (final name in ['/setup', '/settings', '/cast-scan', null]) {
        expect(
          isLibraryLanding(name: name, isFirst: false),
          isFalse,
          reason: '$name is not the library',
        );
      }
    });

    test('the navigator\'s first route is the floor', () {
      // Reached only when no `/home` route is on the chain at all. Without it,
      // `popUntil` would pop the first route too and leave the navigator empty.
      expect(isLibraryLanding(name: null, isFirst: true), isTrue);
      expect(isLibraryLanding(name: '/settings', isFirst: true), isTrue);
    });
  });

  group('popUntil(isLibraryLandingRoute)', () {
    testWidgets('unwinds the player chain to /home', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          initialRoute: kLibraryRouteName,
          routes: {kLibraryRouteName: (_) => const Text('library')},
        ),
      );
      // A search screen sits between the library and the player, exactly as it
      // does in the app (the player is pushed from the search results).
      final nav = tester.state<NavigatorState>(find.byType(Navigator));
      nav.push(
        MaterialPageRoute<void>(
          settings: const RouteSettings(name: '/search'),
          builder: (_) => const Text('search'),
        ),
      );
      await tester.pumpAndSettle();
      await _pushPlayer(tester);
      expect(nav.canPop(), isTrue, reason: 'player above search above library');

      nav.popUntil(isLibraryLandingRoute);
      await tester.pumpAndSettle();

      expect(find.text('player'), findsNothing);
      expect(find.text('search'), findsNothing);
      expect(
        find.text('library'),
        findsOneWidget,
        reason: 'the chain unwinds to the library, not past it',
      );
      expect(nav.canPop(), isFalse, reason: 'nothing is left above it');
      final landing = ModalRoute.of(tester.element(find.text('library')))!;
      expect(landing.settings.name, kLibraryRouteName);
      expect(landing.isCurrent, isTrue);
      expect(tester.takeException(), isNull);
    });

    testWidgets('stops at /home even when /home is not the first route', (
      tester,
    ) async {
      // The setup screen is the app's first route; the library is pushed above it
      // and the player above that. `isFirst` alone would land on the setup
      // screen — this is the case the name clause exists for.
      await tester.pumpWidget(
        MaterialApp(
          home: const Text('setup'),
          routes: {kLibraryRouteName: (_) => const Text('library')},
        ),
      );
      final nav = tester.state<NavigatorState>(find.byType(Navigator));
      nav.pushNamed(kLibraryRouteName);
      await tester.pumpAndSettle();
      await _pushPlayer(tester);

      nav.popUntil(isLibraryLandingRoute);
      await tester.pumpAndSettle();

      final library = ModalRoute.of(tester.element(find.text('library')))!;
      expect(library.isCurrent, isTrue);
      expect(library.isFirst, isFalse, reason: 'the setup screen is below it');
      expect(find.text('player'), findsNothing);
      // The walk stopped AT the library rather than at the navigator's floor:
      // the setup screen is still there, under it. `isFirst` alone would have
      // popped that too and landed the user on the setup screen.
      expect(nav.canPop(), isTrue, reason: 'the library sits above the root');
      expect(
        find.text('setup', skipOffstage: false),
        findsOneWidget,
        reason: 'a covered route is still a live route in the tree',
      );
    });

    testWidgets('with no /home at all it stops at the first route instead of '
        'emptying the navigator', (tester) async {
      await tester.pumpWidget(const MaterialApp(home: Text('setup')));
      final nav = await _pushPlayer(tester);

      nav.popUntil(isLibraryLandingRoute);
      await tester.pumpAndSettle();

      // The floor: the first route is still there, and it is the current one.
      expect(nav.canPop(), isFalse);
      expect(
        ModalRoute.of(tester.element(find.text('setup')))!.isCurrent,
        isTrue,
      );
      expect(find.text('player'), findsNothing);
      expect(
        tester.takeException(),
        isNull,
        reason: 'an empty navigator is a black screen with no way back',
      );
    });

    testWidgets('the player\'s PopScope(canPop: false) does not refuse the pop', (
      tester,
    ) async {
      // `popDisposition` (what `canPop: false` drives) is consulted by
      // `maybePop` only; `popUntil` pops directly. The screen's own handler is
      // still told, with `didPop: true`, so it returns without navigating again.
      await tester.pumpWidget(
        MaterialApp(
          initialRoute: kLibraryRouteName,
          routes: {kLibraryRouteName: (_) => const Text('library')},
        ),
      );
      final invoked = <bool>[];
      final nav = tester.state<NavigatorState>(find.byType(Navigator));
      await _pushPlayer(tester, onPopInvoked: invoked.add);

      nav.popUntil(isLibraryLandingRoute);
      await tester.pumpAndSettle();

      expect(find.text('player'), findsNothing);
      expect(invoked, [
        true,
      ], reason: 'told once, after the pop really happened');
      expect(find.text('library'), findsOneWidget);
    });
  });
}
