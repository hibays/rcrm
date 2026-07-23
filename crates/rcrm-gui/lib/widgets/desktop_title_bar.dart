import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';
import '../providers/window_chrome_provider.dart';

class TitleBarShell extends ConsumerStatefulWidget {
  final Widget child;

  const TitleBarShell({super.key, required this.child});

  @override
  ConsumerState<TitleBarShell> createState() => _TitleBarShellState();
}

class _TitleBarShellState extends ConsumerState<TitleBarShell> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final locked = ref.watch(windowChromeVisibleProvider);
    final immersive = ref.watch(immersiveModeProvider);
    final top = immersive || !locked ? 0.0 : 36.0;

    return Stack(
      children: [
        Positioned.fill(
          top: top,
          child: ClipRect(child: widget.child),
        ),
        if (immersive) ...[
          Listener(
            behavior: HitTestBehavior.translucent,
            onPointerHover: (e) {
              final y = e.localPosition.dy;
              if (y <= 2) {
                if (!_hover && mounted) setState(() => _hover = true);
              } else if (y >= 36) {
                if (_hover && mounted) setState(() => _hover = false);
              }
            },
            child: const SizedBox.expand(),
          ),
          IgnorePointer(
            ignoring: !_hover,
            child: AnimatedOpacity(
              opacity: _hover ? 1.0 : 0.0,
              duration: const Duration(milliseconds: 200),
              child: _DesktopTitleBar(),
            ),
          ),
        ] else if (locked)
          _DesktopTitleBar()
        else
          const SizedBox.shrink(),
      ],
    );
  }
}

class _DesktopTitleBar extends ConsumerStatefulWidget {
  @override
  ConsumerState<_DesktopTitleBar> createState() => _DesktopTitleBarState();
}

class _DesktopTitleBarState extends ConsumerState<_DesktopTitleBar>
    with WindowListener {
  bool _maximized = false;

  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
    _initMaxed();
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    super.dispose();
  }

  @override
  void onWindowMaximize() {
    if (mounted) setState(() => _maximized = true);
  }

  @override
  void onWindowUnmaximize() {
    if (mounted) setState(() => _maximized = false);
  }

  @override
  void onWindowRestore() {
    if (mounted && ref.read(immersiveModeProvider)) {
      windowManager.setFullScreen(true);
    }
  }

  Future<void> _initMaxed() async {
    final m = await windowManager.isMaximized();
    if (mounted) setState(() => _maximized = m);
  }

  void _toggleMax() async {
    if (await windowManager.isMaximized()) {
      await windowManager.unmaximize();
    } else {
      await windowManager.maximize();
    }
  }

  void _toggleImmersive() async {
    final on = !ref.read(immersiveModeProvider);
    ref.read(immersiveModeProvider.notifier).set(on);
    if (on) {
      await windowManager.setFullScreen(true);
    } else {
      await windowManager.setFullScreen(false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final immersive = ref.watch(immersiveModeProvider);
    return Container(
      height: 36,
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A1A),
        border: Border(bottom: BorderSide(color: Color(0x14FFFFFF))),
      ),
      child: SelectionContainer.disabled(
        child: Row(
          children: [
            Expanded(
              child: DragToMoveArea(
                child: SizedBox(
                  height: 36,
                  child: Padding(
                    padding: const EdgeInsets.only(left: 12),
                    child: Row(
                      children: [
                        Image.asset(
                          'macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_128.png',
                          width: 18,
                          height: 18,
                          filterQuality: FilterQuality.high,
                        ),
                        const Spacer(),
                      ],
                    ),
                  ),
                ),
              ),
            ),
            if (immersive) ...[
              const SizedBox(width: 4),
              _TbBtn(
                icon: Icons.remove,
                onTap: () async {
                  await windowManager.setFullScreen(false);
                  await windowManager.minimize();
                },
              ),
              _TbBtn(icon: Icons.fullscreen_exit, onTap: _toggleImmersive),
            ] else ...[
              const SizedBox(width: 4),
              _TbBtn(icon: Icons.fullscreen, onTap: _toggleImmersive),
              _TbBtn(icon: Icons.remove, onTap: windowManager.minimize),
              _TbBtn(
                icon: _maximized ? Icons.filter_none : Icons.crop_square,
                onTap: _toggleMax,
              ),
            ],
            _TbBtn(
              icon: Icons.close,
              onTap: () => windowManager.close(),
              hoverBg: const Color(0xD9FF0000),
            ),
          ],
        ),
      ),
    );
  }
}

class _TbBtn extends StatefulWidget {
  final IconData icon;
  final VoidCallback? onTap;
  final Color? hoverBg;

  const _TbBtn({required this.icon, required this.onTap, this.hoverBg});

  @override
  State<_TbBtn> createState() => _TbBtnState();
}

class _TbBtnState extends State<_TbBtn> {
  bool _hovered = false;
  bool _pressed = false;

  @override
  Widget build(BuildContext context) {
    final bg = _pressed
        ? Colors.white.withValues(alpha: 0.15)
        : _hovered
        ? (widget.hoverBg ?? Colors.white.withValues(alpha: 0.10))
        : Colors.transparent;

    return MouseRegion(
      onEnter: (_) => setState(() => _hovered = true),
      onExit: (_) => setState(() => _hovered = false),
      child: GestureDetector(
        onTapDown: (_) => setState(() => _pressed = true),
        onTapUp: (_) => setState(() => _pressed = false),
        onTapCancel: () => setState(() => _pressed = false),
        onTap: widget.onTap,
        child: Container(
          width: 46,
          height: 36,
          color: bg,
          alignment: Alignment.center,
          child: Icon(widget.icon, color: Colors.white70, size: 16),
        ),
      ),
    );
  }
}
