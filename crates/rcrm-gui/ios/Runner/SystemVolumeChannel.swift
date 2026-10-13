import AVFoundation
import Flutter
import MediaPlayer
import UIKit

/// The `rcrm/volume` channel — the iOS half of the mobile volume binding
/// (`lib/services/system_volume.dart`).
///
/// iOS has ONE output volume, moved by the hardware buttons and by the system's
/// own volume HUD, and there is no per-app mixer. So the player's volume control
/// moves that same number here too, and the player itself stays wide open.
///
/// Reading is public API: `AVAudioSession.outputVolume` is key-value observable,
/// which is also how a change made with the hardware buttons reaches the bar.
/// Writing is the well-known exception: iOS exposes no setter, and the only
/// supported route is the `UISlider` INSIDE an `MPVolumeView` — so one is kept
/// in the key window (offscreen, and not hidden: a view that is not in the
/// hierarchy has no slider driving the system) and its slider is set and
/// "touched". When no slider can be found, nothing is written and the reading
/// that goes back is the volume the device really has, so the bar can never show
/// a level the phone is not at.
///
/// The numbers crossed here are the platform's own: 0...100, which on iOS is
/// already the percentage — the arithmetic in Dart (and the quantisation it
/// handles on Android) is a no-op on this platform by construction.
final class SystemVolumeChannel: NSObject {
  static let methodChannelName = "rcrm/volume"

  /// Where the last audible level is kept — the same fact the Android half
  /// remembers in its own preferences, and for the same reason: the question it
  /// answers ("the phone is at 0; what should unmute restore?") is asked at the
  /// START of a session, and an in-memory value would have nothing to say then.
  private static let lastAudibleKey = "rcrm_last_audible_output_volume"

  private var channel: FlutterMethodChannel?
  private var volumeView: MPVolumeView?
  private var observing = false

  /// Wires the channel up. The caller (the app delegate) holds the returned
  /// object: it owns the volume observer.
  static func register(with registrar: FlutterPluginRegistrar) -> SystemVolumeChannel {
    let instance = SystemVolumeChannel()
    let channel = FlutterMethodChannel(
      name: methodChannelName, binaryMessenger: registrar.messenger())
    instance.channel = channel
    // `[weak instance]`: the channel retains this closure and the instance
    // retains the channel (it needs it to push `onChanged`), so a strong capture
    // would keep the observer — and this object — alive for the whole process,
    // making `deinit` (the only place the volume observer comes off) dead code.
    channel.setMethodCallHandler { [weak instance] call, result in
      guard let instance = instance else {
        result(FlutterMethodNotImplemented)
        return
      }
      switch call.method {
      case "read":
        result(instance.reading())
      case "setIndex":
        // Both directions answer with the same shape: what the device's volume
        // is NOW. The caller never gets back what it asked for, only what it got.
        if let index = (call.arguments as? [String: Any])?["index"] as? Int {
          instance.apply(index)
        }
        result(instance.reading())
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    instance.startObserving()
    return instance
  }

  /// The device's output volume, in the platform's own numbers.
  ///
  /// `fixed` is not something iOS reports — there is no `isVolumeFixed()` here —
  /// so the only honest signal is the control this app writes through
  /// ([outputHasNoVolumeControl]).
  private func reading() -> [String: Any] {
    let index = currentIndex
    if index > 0 {
      lastAudible = index
    }
    return [
      "index": index,
      "min": 0,
      "max": 100,
      "muted": index <= 0,
      "lastAudible": lastAudible,
      "fixed": outputHasNoVolumeControl,
    ]
  }

  /// The current output volume, as a percentage.
  ///
  /// The volume view's own slider is preferred over `AVAudioSession.outputVolume`
  /// because it is the SAME control this app writes through, so reading and
  /// writing cannot describe two different things — and because `outputVolume` is
  /// only meaningful once the audio session is active, which this app must not
  /// force (activating it would interrupt whatever else is playing, and a video
  /// that has not started yet has no session of its own).
  private var currentIndex: Int {
    if let slider = volumeSlider() {
      return clampIndex(Int((slider.value * 100).rounded()))
    }
    return clampIndex(Int((AVAudioSession.sharedInstance().outputVolume * 100).rounded()))
  }

  private func clampIndex(_ value: Int) -> Int {
    return min(max(value, 0), 100)
  }

  /// True when there is no volume control to write through — a route that offers
  /// none (some AirPlay sinks, receivers, docks), where `apply` would otherwise
  /// return without doing anything.
  ///
  /// The failure is asymmetric, so this answer is deliberately pessimistic: a
  /// wrong "fixed" costs the app its binding (the player keeps its own volume,
  /// which always works), while a wrong "settable" costs the user EVERY volume
  /// control there is — libmpv pinned at unity and a slider that writes nothing.
  ///
  /// It is asked about a view this app has already built ([volumeView], created by
  /// the [currentIndex] read above); a missing view reads as "no control".
  private var outputHasNoVolumeControl: Bool {
    return volumeView?.subviews.contains { $0 is UISlider } != true
  }

  private var lastAudible: Int {
    get { UserDefaults.standard.integer(forKey: SystemVolumeChannel.lastAudibleKey) }
    set { UserDefaults.standard.set(newValue, forKey: SystemVolumeChannel.lastAudibleKey) }
  }

  private func apply(_ index: Int) {
    let clamped = min(max(index, 0), 100)
    guard let slider = volumeSlider() else { return }
    if clamped > 0 {
      lastAudible = clamped
    }
    slider.value = Float(clamped) / 100
    // Setting the value alone does not move anything: the system listens for the
    // control event the thumb would have sent.
    slider.sendActions(for: .touchUpInside)
  }

  /// The slider inside the offscreen volume view, which is the only way to set
  /// the output volume from an app.
  private func volumeSlider() -> UISlider? {
    let view = volumeView(in: keyWindow)
    return view.subviews.compactMap { $0 as? UISlider }.first
  }

  private func volumeView(in window: UIWindow?) -> MPVolumeView {
    if let existing = volumeView {
      // The window can change under us (a scene reconnecting); the view has to
      // be in one for its slider to drive the system.
      if existing.superview == nil, let window = window {
        window.addSubview(existing)
      }
      return existing
    }
    let view = MPVolumeView(
      frame: CGRect(x: -1000, y: -1000, width: 160, height: 40))
    view.showsRouteButton = false
    // Not `isHidden` and not alpha 0: a view the system does not consider
    // visible has no working slider.
    view.alpha = 0.0001
    if let window = window {
      window.addSubview(view)
    }
    view.layoutIfNeeded()
    volumeView = view
    return view
  }

  private var keyWindow: UIWindow? {
    for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
      if let window = scene.windows.first(where: { $0.isKeyWindow }) {
        return window
      }
      if let window = scene.windows.first {
        return window
      }
    }
    return nil
  }

  /// Follows the output volume, so a change made with the hardware buttons (or
  /// by the system's own HUD) still reaches the bar.
  private func startObserving() {
    guard !observing else { return }
    observing = true
    AVAudioSession.sharedInstance().addObserver(
      self, forKeyPath: "outputVolume", options: [.new], context: nil)
  }

  private func stopObserving() {
    guard observing else { return }
    observing = false
    AVAudioSession.sharedInstance().removeObserver(self, forKeyPath: "outputVolume")
  }

  override func observeValue(
    forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?,
    context: UnsafeMutableRawPointer?
  ) {
    guard keyPath == "outputVolume" else { return }
    // Not documented as main-thread; the channel is.
    DispatchQueue.main.async { [weak self] in
      guard let self = self else { return }
      self.channel?.invokeMethod("onChanged", arguments: self.reading())
    }
  }

  deinit {
    stopObserving()
  }
}
