// test/image_load_gate_test.dart
// The image decode gate is a LIFO stack: newest served first, a repeat request
// raised to the top, and a waiting request is never dropped (a dropped token is
// completed, so its caller decodes outside the concurrency cap and in request
// order). The last group pins the wiring, asserting the order the server is
// actually asked in.

import 'dart:async';
import 'dart:io';

import 'package:flutter/painting.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/image_load_gate.dart';
import 'package:rcrm_gui/services/item_cache_limit.dart';
import 'package:rcrm_gui/services/net.dart';
import 'package:rcrm_gui/services/thumb_cache.dart';
import 'package:rcrm_gui/widgets/disk_thumb_image.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final gate = ImageLoadGate.instance;
  final slots = ItemCacheLimit.imageDecodeConcurrency;

  /// Every token a test takes, so the singleton is left clean for the next one
  /// (each test file runs in its own isolate, but not each test).
  final held = <Completer<void>>[];

  /// Pushes a request and remembers it for the tear-down.
  Completer<void> push() {
    final token = gate.acquire();
    held.add(token);
    return token;
  }

  tearDown(() {
    for (final token in held) {
      gate.done(token);
    }
    held.clear();
    expect(gate.runningCount, 0, reason: 'a test leaked a decode slot');
    expect(gate.waitingCount, 0, reason: 'a test leaked a stacked request');
  });

  group('the stack', () {
    test('a free gate grants immediately, up to the concurrency cap', () {
      final tokens = [for (var i = 0; i < slots; i++) push()];
      expect(tokens.every((t) => t.isCompleted), isTrue);
      expect(gate.runningCount, slots);

      // One past the cap waits instead of running.
      final extra = push();
      expect(extra.isCompleted, isFalse);
      expect(gate.waitingCount, 1);
    });

    test('the newest waiting request is served first', () {
      final running = [for (var i = 0; i < slots; i++) push()];
      final oldest = push();
      final middle = push();
      final newest = push();
      expect([oldest, middle, newest].every((t) => t.isCompleted), isFalse);

      gate.done(running.first);

      // The TOP of the stack, not the bottom — the whole change.
      expect(newest.isCompleted, isTrue, reason: 'the newest request waited');
      expect(middle.isCompleted, isFalse);
      expect(oldest.isCompleted, isFalse);
    });

    test('the stack drains from the top down', () {
      final running = [for (var i = 0; i < slots; i++) push()];
      final oldest = push();
      final middle = push();
      final newest = push();

      gate.done(running[0]);
      expect(newest.isCompleted, isTrue);
      gate.done(newest);
      expect(middle.isCompleted, isTrue);
      gate.done(middle);
      expect(oldest.isCompleted, isTrue);
    });

    test('a repeat request moves a waiting image to the top', () {
      final running = [for (var i = 0; i < slots; i++) push()];
      final first = push();
      final second = push();
      final third = push();

      // The reader scrolled back to the FIRST image: the request that is already
      // queued is now the most recent statement of what is wanted.
      gate.restack(first);

      gate.done(running.first);
      expect(first.isCompleted, isTrue, reason: 'the restacked request waited');
      expect(second.isCompleted, isFalse);
      expect(third.isCompleted, isFalse);
    });

    test('restacking a running request changes nothing', () {
      final running = [for (var i = 0; i < slots; i++) push()];
      final first = push();
      final second = push();

      gate.restack(running.first); // already holds a slot: no stack position

      gate.done(running[1]);
      expect(second.isCompleted, isTrue);
      expect(first.isCompleted, isFalse);
    });

    test('a request abandoned before its turn leaves the stack', () {
      final running = [for (var i = 0; i < slots; i++) push()];
      final oldest = push();
      final abandoned = push();
      final newest = push();

      // The cell scrolled off before its slot came up (PooledImage._teardown).
      gate.done(abandoned);
      expect(abandoned.isCompleted, isTrue, reason: 'its caller would hang');
      expect(gate.waitingCount, 2);

      gate.done(running.first);
      expect(newest.isCompleted, isTrue);
      expect(oldest.isCompleted, isFalse);
    });

    test('a long stack keeps every request open: nothing is dropped', () {
      for (var i = 0; i < slots; i++) {
        push();
      }
      final stacked = [for (var i = 0; i < 30; i++) push()];

      // A dropped token is completed, and both callers read completion as "a
      // slot is yours": the oldest (top-of-folder) requests would then decode
      // outside the concurrency cap, in request order — the FIFO behaviour the
      // stack replaced. Waiting must leave every future open.
      expect(gate.waitingCount, 30);
      expect(stacked.any((token) => token.isCompleted), isFalse);

      gate.done(stacked.last);
      expect(gate.waitingCount, 29, reason: 'an abandoned waiter is removed');
    });

    test('the running count never exceeds the cap', () {
      final running = [for (var i = 0; i < slots; i++) push()];
      final stacked = [for (var i = 0; i < 5; i++) push()];

      // Drain the stack one slot at a time, top first: every grant must land
      // inside the cap, and each release must hand the slot on rather than
      // leaving it free while work waits.
      gate.done(running.first);
      var released = 0;
      for (final token in stacked.reversed) {
        expect(gate.runningCount, lessThanOrEqualTo(slots));
        if (token.isCompleted) {
          gate.done(token);
          released++;
        }
      }
      expect(released, 5, reason: 'the stack drained one slot at a time');
      expect(gate.runningCount, lessThanOrEqualTo(slots));
    });
  });

  group('DiskThumbImage asks the server in stack order', () {
    late HttpServer server;
    final streams = <ImageStream>[];
    final listeners = <ImageStreamListener>[];

    setUp(() async {
      // The test binding installs a mock HttpClient that answers 400 to
      // everything; these tests talk to a real loopback server.
      HttpOverrides.global = null;
      setSharedAuth(null);
      ThumbCache.enabled = false;
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    });

    tearDown(() async {
      for (var i = 0; i < listeners.length; i++) {
        streams[i].removeListener(listeners[i]);
      }
      streams.clear();
      listeners.clear();
      setSharedAuth(null);
      await server.close(force: true);
    });

    /// Resolves [url]'s thumbnail. Every outcome is irrelevant here — only the
    /// ORDER of the requests is under test — so the error is swallowed.
    void ask(String url) {
      final stream = DiskThumbImage(
        url,
        64,
      ).resolve(const ImageConfiguration());
      final listener = ImageStreamListener((_, _) {}, onError: (_, _) {});
      stream.addListener(listener);
      streams.add(stream);
      listeners.add(listener);
    }

    test('the picture the reader came back to is fetched first', () async {
      final seen = <String>[];
      server.listen((req) async {
        seen.add(req.uri.path);
        req.response.statusCode = 200;
        // Not an image: the decode fails, which is fine — the request itself is
        // what this test is about.
        req.response.add(const [0, 1, 2, 3]);
        await req.response.close();
      });
      String url(String name) => 'http://127.0.0.1:${server.port}/$name';

      Future<void> until(bool Function() condition, String what) async {
        final deadline = DateTime.now().add(const Duration(seconds: 10));
        while (!condition()) {
          if (DateTime.now().isAfter(deadline)) {
            fail('timed out waiting for $what');
          }
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
      }

      // Saturate the gate, so every thumbnail below is only QUEUED — the state a
      // reader's scroll leaves the gate in.
      final running = [for (var i = 0; i < slots; i++) push()];

      ask(url('a.jpg'));
      await until(() => gate.waitingCount == 1, 'a to be queued');
      ask(url('b.jpg'));
      await until(() => gate.waitingCount == 2, 'b to be queued');
      ask(url('c.jpg'));
      await until(() => gate.waitingCount == 3, 'c to be queued');

      // The reader goes back to the first picture. It is already queued, so the
      // request is deduped and restacked rather than pushed again.
      ask(url('a.jpg'));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(gate.waitingCount, 3, reason: 'a second fetch for one image');

      // One slot frees: the restacked request takes it, then the stack drains
      // from its top down (a, c, b) as each generation releases its slot.
      gate.done(running.first);
      // Wait for the DRAIN, not just for the third request to arrive: a
      // generation releases its slot only after its decode has failed, and
      // ending the test in between would leave the next test holding one
      // (the tear-down below says so).
      await until(
        () => gate.waitingCount == 0 && gate.runningCount == slots - 1,
        'the stack to drain',
      );

      expect(seen, ['/a.jpg', '/c.jpg', '/b.jpg']);
    });
  });
}
