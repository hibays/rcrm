import 'package:flutter_riverpod/flutter_riverpod.dart';

class WindowChromeNotifier extends Notifier<bool> {
  @override
  bool build() => true;

  void setVisible(bool v) => state = v;
  void toggle() => state = !state;
}

final windowChromeVisibleProvider =
    NotifierProvider<WindowChromeNotifier, bool>(WindowChromeNotifier.new);

class ImmersiveNotifier extends Notifier<bool> {
  @override
  bool build() => false;

  void toggle() => state = !state;
  void set(bool v) => state = v;
}

final immersiveModeProvider = NotifierProvider<ImmersiveNotifier, bool>(
  ImmersiveNotifier.new,
);
