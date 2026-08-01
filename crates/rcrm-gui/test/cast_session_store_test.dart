// test/cast_session_store_test.dart
// Unit tests for the persisted cast pairing store (round-trip + corruption).

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/cast_protocol.dart';
import 'package:rcrm_gui/services/cast_session_store.dart';
import 'package:shared_preferences/shared_preferences.dart';

CastQrPayload _qr() => CastQrPayload(
  host: '192.168.1.5',
  port: 8901,
  token: 'a' * 64,
  certSha256: 'b' * 64,
  name: 'rcrm-tv',
);

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  test('round-trips a pairing', () async {
    final store = CastSessionStore();
    await store.save(qr: _qr(), session: 'c' * 64);
    final loaded = await store.load();
    expect(loaded, isNotNull);
    expect(loaded!.qr.host, '192.168.1.5');
    expect(loaded.qr.port, 8901);
    expect(loaded.qr.certSha256, 'b' * 64);
    expect(loaded.qr.name, 'rcrm-tv');
    expect(loaded.session, 'c' * 64);
  });

  test('clear removes the pairing', () async {
    final store = CastSessionStore();
    await store.save(qr: _qr(), session: 'c' * 64);
    await store.clear();
    expect(await store.load(), isNull);
  });

  test('load returns null on empty store', () async {
    expect(await CastSessionStore().load(), isNull);
  });

  test('load returns null on corrupt payload', () async {
    SharedPreferences.setMockInitialValues({
      'cast_session_v1': '{"host":"x","port":8901,"certSha256":"nope"}',
    });
    expect(await CastSessionStore().load(), isNull);
  });
}
