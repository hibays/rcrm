// widgets/cast_receiver_qr_view.dart
// The cast receiver's QR pairing page, extracted from CastReceiverScreen so
// it can be rendered and tested in isolation (the screen itself needs the
// Rust bridge, which widget tests cannot load).
//
// Responsive: landscape (TV, desktop, landscape phones) shows info + QR
// side by side; portrait shows a stacked, scrollable column.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../ffi/rust_bridge.dart';
import '../services/cast_protocol.dart';

/// The white QR card. When [badge] is non-null the QR is dimmed and struck
/// through with a badge (expired / already paired) while the layout stays
/// unchanged.
///
/// The code itself is generated in Rust (`rcrm_generate_qr_webp` — rxing
/// encoder → 2048×2048 lossless WebP) instead of qr_flutter, so the Dart
/// side has no QR dependency and the TV never re-renders a vector QR.
class CastReceiverQrCard extends StatefulWidget {
  final CastQrPayload qr;
  final double size;
  final String? badge;
  const CastReceiverQrCard({
    super.key,
    required this.qr,
    required this.size,
    this.badge,
  });

  @override
  State<CastReceiverQrCard> createState() => _QrCardState();
}

class _QrCardState extends State<CastReceiverQrCard> {
  /// Payload → WebP bytes. Pairing payloads are short-lived tokens; the
  /// cache only avoids regenerating when the same payload reappears (e.g.
  /// the badge toggles rebuild the card with an identical code).
  static final Map<String, Uint8List> _webpCache = {};

  Uint8List? _webp;

  /// Bumped on every payload change so a stale in-flight `generateQrWebp`
  /// (it is a synchronous FFI call, but the cache-miss path can interleave
  /// with a second payload change) can never overwrite the QR of the
  /// current payload — pairing would otherwise scan an expired token.
  int _gen = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void didUpdateWidget(CastReceiverQrCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.qr.encode() != widget.qr.encode()) {
      _gen++;
      _load();
    }
  }

  Future<void> _load() async {
    final gen = _gen;
    final payload = widget.qr.encode();
    final cached = _webpCache[payload];
    if (cached != null) {
      if (mounted) setState(() => _webp = cached);
      return;
    }
    final bytes = RustBridge().generateQrWebp(payload);
    if (bytes == null || gen != _gen) {
      return; // keep whatever we had (or placeholder)
    }
    if (_webpCache.length > 16) _webpCache.remove(_webpCache.keys.first);
    _webpCache[payload] = bytes;
    if (mounted) setState(() => _webp = bytes);
  }

  @override
  Widget build(BuildContext context) {
    final size = widget.size;
    final webp = _webp;
    return Container(
      // Small padding only — the QR's own 4-module quiet zone (baked into
      // the generated image) is the real white margin. A larger padding
      // would shrink the visible code for no scanning benefit.
      padding: EdgeInsets.all(size * 0.02),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(size * 0.07),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF4C6FFF).withValues(alpha: 0.35),
            blurRadius: 40,
            spreadRadius: 2,
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(size * 0.03),
        child: Stack(
          children: [
            SizedBox(
              width: size,
              height: size,
              child: webp != null
                  ? Image.memory(
                      webp,
                      fit: BoxFit.contain,
                      gaplessPlayback: true,
                      errorBuilder: (_, _, _) => const SizedBox.shrink(),
                    )
                  : const Center(
                      child: SizedBox(
                        width: 24,
                        height: 24,
                        child: CircularProgressIndicator(
                          strokeWidth: 2.5,
                          color: Color(0xFF101428),
                        ),
                      ),
                    ),
            ),
            if (widget.badge != null)
              Positioned.fill(
                child: ColoredBox(
                  color: Colors.black.withValues(alpha: 0.45),
                  child: CustomPaint(
                    painter: const _StrikeThroughPainter(),
                    child: Center(
                      child: Container(
                        // Cap the pill at ~70% of the card so the badge text
                        // never sprawls to the card edges on small portrait
                        // cards (the strike-through painter still crosses the
                        // whole card, but the pill keeps a compact shape).
                        constraints: BoxConstraints(
                          maxWidth: widget.size * 0.7,
                        ),
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 8,
                        ),
                        decoration: BoxDecoration(
                          color: const Color(
                            0xFF101428,
                          ).withValues(alpha: 0.85),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(
                            color: Colors.white.withValues(alpha: 0.5),
                          ),
                        ),
                        child: Text(
                          widget.badge!,
                          textAlign: TextAlign.center,
                          maxLines: 3,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                            color: Colors.white,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Paints an X across the QR to mark it invalid.
class _StrikeThroughPainter extends CustomPainter {
  const _StrikeThroughPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withValues(alpha: 0.75)
      ..strokeWidth = size.shortestSide * 0.02
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(
      Offset(size.width * 0.08, size.height * 0.08),
      Offset(size.width * 0.92, size.height * 0.92),
      paint,
    );
    canvas.drawLine(
      Offset(size.width * 0.92, size.height * 0.08),
      Offset(size.width * 0.08, size.height * 0.92),
      paint,
    );
  }

  @override
  bool shouldRepaint(_StrikeThroughPainter oldDelegate) => false;
}

class _BrandHeader extends StatelessWidget {
  const _BrandHeader();

  @override
  Widget build(BuildContext context) {
    // FittedBox: "Cast Receiver" at 30px is wider than a narrow portrait
    // phone's content column and previously overflowed the right edge (the
    // "black bar" on the right side of the QR page). scaleDown shrinks the
    // whole header to fit any width; on wide screens it stays full-size.
    return FittedBox(
      fit: BoxFit.scaleDown,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [Color(0xFF6C8CFF), Color(0xFF9A6CFF)],
              ),
              borderRadius: BorderRadius.circular(14),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF6C8CFF).withValues(alpha: 0.4),
                  blurRadius: 18,
                ),
              ],
            ),
            child: const Icon(Icons.cast, color: Colors.white, size: 30),
          ),
          const SizedBox(width: 14),
          const Text(
            'Cast Receiver',
            style: TextStyle(
              fontSize: 30,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }
}

/// Shows the seconds left until the one-time pair token expires. On expiry
/// the token is destroyed (receiver stops offering the QR) and the parent
/// switches to the expired state; this widget itself stays stateless.
class _PairCountdown extends StatelessWidget {
  final DateTime? expiresAt;
  final bool paired;
  final bool tick;
  const _PairCountdown({
    required this.expiresAt,
    required this.paired,
    required this.tick,
  });

  @override
  Widget build(BuildContext context) {
    if (paired) {
      return Text(
        'Paired - QR no longer needed',
        style: TextStyle(
          fontSize: 13,
          color: Colors.white.withValues(alpha: 0.45),
        ),
      );
    }
    final exp = expiresAt;
    if (exp == null) return const SizedBox.shrink();
    final left = exp.difference(DateTime.now());
    if (left.isNegative) {
      return Text(
        'Code expired and destroyed',
        style: const TextStyle(
          fontSize: 13,
          color: Color(0xFFFFB74D),
          fontWeight: FontWeight.w600,
        ),
      );
    }
    final secs = (left.inMilliseconds / 1000).ceil();
    final urgent = secs <= 15;
    return Text(
      'Code expires in ${secs}s',
      style: TextStyle(
        fontSize: 13,
        color: urgent
            ? const Color(0xFFFFB74D)
            : Colors.white.withValues(alpha: 0.45),
        fontWeight: urgent ? FontWeight.w600 : FontWeight.normal,
      ),
    );
  }
}

class _StatusChip extends StatelessWidget {
  final String label;
  final bool ok;
  final IconData icon;
  const _StatusChip({
    required this.label,
    required this.ok,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    final bg = ok
        ? const Color(0xFF1B5E20).withValues(alpha: 0.85)
        : const Color(0xFF4A148C).withValues(alpha: 0.85);
    final fg = ok ? const Color(0xFFA5D6A7) : const Color(0xFFCE93D8);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: fg.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: fg),
          const SizedBox(width: 7),
          Text(
            label,
            style: TextStyle(
              fontSize: 14,
              color: fg,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }
}

/// Callbacks the QR page needs from its host screen.
class CastReceiverQrViewCallbacks {
  final VoidCallback onUnpair;
  final VoidCallback onRegenerate;
  final ValueChanged<String> onSelectIpv4;
  const CastReceiverQrViewCallbacks({
    required this.onUnpair,
    required this.onRegenerate,
    required this.onSelectIpv4,
  });
}

/// The QR pairing page body: branded gradient, status chips, countdown,
/// address selector and the QR card. Portrait/landscape responsive.
class CastReceiverQrView extends StatelessWidget {
  final CastQrPayload qr;
  final bool paired;
  final bool usable;
  final String? badge;
  final bool showBack;
  final List<String> localIpv4s;
  final DateTime? pairExpiresAt;
  final bool serverOk;
  final bool tick;
  final CastReceiverQrViewCallbacks callbacks;

  const CastReceiverQrView({
    super.key,
    required this.qr,
    required this.paired,
    required this.usable,
    required this.badge,
    required this.showBack,
    required this.localIpv4s,
    required this.pairExpiresAt,
    required this.serverOk,
    required this.tick,
    required this.callbacks,
  });

  @override
  Widget build(BuildContext context) {
    // No AppBar: the gradient covers the ENTIRE screen edge to edge.
    // When showBack is set, a back button is drawn inside the gradient
    // over the SafeArea instead.
    return Scaffold(
      backgroundColor: Colors.transparent,
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF101428), Color(0xFF1A1030), Color(0xFF0B0B14)],
          ),
        ),
        child: SafeArea(
          child: Stack(
            children: [
              Positioned.fill(
                child: LayoutBuilder(
                  builder: (context, constraints) {
                    // Landscape (TV, desktop windows, landscape phones):
                    // side-by-side info + QR. Portrait: stacked, centered.
                    final landscape =
                        constraints.maxWidth > 700 &&
                        constraints.maxWidth > constraints.maxHeight * 1.02;
                    if (landscape) {
                      return _buildLandscape(context, constraints);
                    }
                    return _buildPortrait(context, constraints);
                  },
                ),
              ),
              if (showBack)
                Positioned(
                  top: 4,
                  left: 4,
                  child: IconButton(
                    tooltip: 'Back',
                    onPressed: () => Navigator.of(context).maybePop(),
                    icon: const Icon(Icons.arrow_back, color: Colors.white),
                    style: IconButton.styleFrom(
                      backgroundColor: Colors.white.withValues(alpha: 0.08),
                      side: BorderSide(
                        color: Colors.white.withValues(alpha: 0.15),
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildLandscape(BuildContext context, BoxConstraints constraints) {
    final qrSize = (constraints.maxHeight * 0.52).clamp(220.0, 520.0);
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 1280),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 24),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Left: brand + status + actions. Scrollable so a short
              // landscape window (phone held sideways) never overflows
              // vertically — previously the fixed Column clipped.
              Expanded(
                flex: 5,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const _BrandHeader(),
                      const SizedBox(height: 20),
                      Text(
                        paired
                            ? 'Phone connected, waiting to play...'
                            : usable
                            ? 'Scan the QR with the RCrm phone app'
                            : 'Code expired - tap below for a new one',
                        style: TextStyle(
                          fontSize: 18,
                          color: Colors.white.withValues(alpha: 0.75),
                        ),
                      ),
                      const SizedBox(height: 28),
                      Wrap(
                        spacing: 12,
                        runSpacing: 10,
                        children: [
                          _StatusChip(
                            label: paired ? 'Paired' : 'Waiting to scan',
                            ok: paired,
                            icon: paired
                                ? Icons.check_circle
                                : Icons.radio_button_checked,
                          ),
                          _StatusChip(
                            label: serverOk
                                ? 'Server reachable'
                                : 'Server not connected',
                            ok: serverOk,
                            icon: serverOk ? Icons.cloud_done : Icons.cloud_off,
                          ),
                        ],
                      ),
                      const SizedBox(height: 20),
                      _buildAddressRow(qr, landscape: true),
                      const SizedBox(height: 26),
                      _PairCountdown(
                        expiresAt: pairExpiresAt,
                        paired: paired,
                        tick: tick,
                      ),
                      const SizedBox(height: 16),
                      Focus(
                        child: OutlinedButton.icon(
                          onPressed: paired
                              ? callbacks.onUnpair
                              : callbacks.onRegenerate,
                          style: OutlinedButton.styleFrom(
                            foregroundColor: Colors.white,
                            side: BorderSide(
                              color: Colors.white.withValues(alpha: 0.35),
                            ),
                            padding: const EdgeInsets.symmetric(
                              horizontal: 20,
                              vertical: 12,
                            ),
                          ),
                          icon: Icon(paired ? Icons.link_off : Icons.qr_code_2),
                          label: Text(paired ? 'Unpair' : 'New code'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 48),
              // Right: the QR card.
              Expanded(
                flex: 4,
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    CastReceiverQrCard(qr: qr, size: qrSize, badge: badge),
                    const SizedBox(height: 14),
                    Text(
                      'One-time code, auto-destroys on expiry',
                      style: TextStyle(
                        fontSize: 13,
                        color: Colors.white.withValues(alpha: 0.4),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPortrait(BuildContext context, BoxConstraints constraints) {
    final shortSide = constraints.maxWidth < constraints.maxHeight
        ? constraints.maxWidth
        : constraints.maxHeight;
    final qrSize = (shortSide * 0.42).clamp(180.0, 430.0);
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: constraints.maxHeight - 40),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const _BrandHeader(),
            const SizedBox(height: 12),
            Text(
              paired
                  ? 'Phone connected, waiting to play...'
                  : usable
                  ? 'Scan the QR with the RCrm phone app'
                  : 'Code expired - tap below for a new one',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 17,
                color: Colors.white.withValues(alpha: 0.75),
              ),
            ),
            const SizedBox(height: 28),
            // QR card — the pairing surface.
            CastReceiverQrCard(qr: qr, size: qrSize, badge: badge),
            const SizedBox(height: 20),
            _PairCountdown(
              expiresAt: pairExpiresAt,
              paired: paired,
              tick: tick,
            ),
            const SizedBox(height: 20),
            Wrap(
              spacing: 12,
              runSpacing: 10,
              alignment: WrapAlignment.center,
              children: [
                _StatusChip(
                  label: paired ? 'Paired' : 'Waiting to scan',
                  ok: paired,
                  icon: paired
                      ? Icons.check_circle
                      : Icons.radio_button_checked,
                ),
                _StatusChip(
                  label: serverOk ? 'Server reachable' : 'Server not connected',
                  ok: serverOk,
                  icon: serverOk ? Icons.cloud_done : Icons.cloud_off,
                ),
              ],
            ),
            const SizedBox(height: 18),
            _buildAddressRow(qr, landscape: false),
            const SizedBox(height: 22),
            Focus(
              child: OutlinedButton.icon(
                onPressed: paired ? callbacks.onUnpair : callbacks.onRegenerate,
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.white,
                  side: BorderSide(color: Colors.white.withValues(alpha: 0.35)),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 12,
                  ),
                ),
                icon: Icon(paired ? Icons.link_off : Icons.qr_code_2),
                label: Text(paired ? 'Unpair' : 'New code'),
              ),
            ),
            const SizedBox(height: 10),
            Text(
              'One-time code, auto-destroys on expiry',
              style: TextStyle(
                fontSize: 13,
                color: Colors.white.withValues(alpha: 0.4),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAddressRow(CastQrPayload qr, {required bool landscape}) {
    final style = TextStyle(
      fontSize: landscape ? 15 : 14,
      color: Colors.white.withValues(alpha: 0.55),
    );
    final label = 'Address ${qr.host}:${qr.port}';
    if (localIpv4s.length <= 1) {
      return Align(
        alignment: landscape ? Alignment.centerLeft : Alignment.center,
        child: Text(label, style: style),
      );
    }
    return Row(
      mainAxisSize: MainAxisSize.min,
      mainAxisAlignment: landscape
          ? MainAxisAlignment.start
          : MainAxisAlignment.center,
      children: [
        Text(label, style: style),
        const SizedBox(width: 4),
        PopupMenuButton<String>(
          tooltip: 'Change LAN address',
          icon: Icon(
            Icons.swap_horiz,
            size: 16,
            color: Colors.white.withValues(alpha: 0.55),
          ),
          onSelected: callbacks.onSelectIpv4,
          itemBuilder: (context) => [
            for (final ip in localIpv4s)
              PopupMenuItem<String>(
                value: ip,
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (ip == qr.host)
                      const Icon(Icons.check, size: 16)
                    else
                      const SizedBox(width: 16),
                    const SizedBox(width: 8),
                    Text(ip),
                  ],
                ),
              ),
          ],
        ),
      ],
    );
  }
}
