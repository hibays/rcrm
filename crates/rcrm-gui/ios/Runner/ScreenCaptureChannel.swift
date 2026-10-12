import Flutter
import UIKit

/// The `rcrm/screen` channel — the iOS half of the app's screenshot policy
/// (`lib/services/screen_capture.dart`).
///
/// iOS has no `FLAG_SECURE`. A still screenshot cannot be refused, and the only
/// notice an app gets is `userDidTakeScreenshotNotification` — after the fact.
/// What the platform does expose is whether the screen is being recorded,
/// mirrored or streamed (`UIScreen.isCaptured`), and the moment the app stops
/// being frontmost, which is when the system photographs it for the app
/// switcher. This channel covers the library in both of those situations, which
/// is the honest half of the policy; the Settings row states exactly that much
/// and no more.
///
/// The cover is a plain view in the key window, so it hides the Flutter view
/// without touching the engine. It comes off as soon as the app is frontmost
/// again and nothing is capturing.
///
/// `NSObject` because the observers are selector-based: `#selector` only reaches
/// methods exposed to Objective-C, which a plain Swift class does not have.
final class ScreenCaptureChannel: NSObject {
  static let methodChannelName = "rcrm/screen"

  /// The colour the app paints behind everything (`RCrmColors.pitch`), so the
  /// cover reads as the app rather than as a system error.
  private static let coverColor = UIColor(
    red: 0x0E / 255.0, green: 0x0E / 255.0, blue: 0x0E / 255.0, alpha: 1)

  private var allowCapture = false
  private var observing = false
  private var cover: UIView?

  /// Wires the channel up. The caller (the app delegate) holds the returned
  /// object: it owns the notification observers.
  static func register(with registrar: FlutterPluginRegistrar) -> ScreenCaptureChannel {
    let instance = ScreenCaptureChannel()
    let channel = FlutterMethodChannel(
      name: methodChannelName, binaryMessenger: registrar.messenger())
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "setCaptureAllowed":
        // An absent argument means "do not allow": the safe half of a
        // malformed call.
        let allowed = (call.arguments as? [String: Any])?["allowed"] as? Bool ?? false
        instance.setCaptureAllowed(allowed)
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    // Fail closed, like the Android half: the native default is NOT capturable,
    // so the observers are armed from the first moment and the stored choice
    // Dart sends a few frames later is what turns them off.
    instance.setCaptureAllowed(false)
    return instance
  }

  private func setCaptureAllowed(_ allowed: Bool) {
    allowCapture = allowed
    if allowed {
      stopObserving()
      removeCover()
    } else {
      startObserving()
      updateCover()
    }
  }

  private func startObserving() {
    guard !observing else { return }
    observing = true
    let center = NotificationCenter.default
    center.addObserver(
      self, selector: #selector(stateChanged),
      name: UIScreen.capturedDidChangeNotification, object: nil)
    center.addObserver(
      self, selector: #selector(stateChanged),
      name: UIApplication.willResignActiveNotification, object: nil)
    center.addObserver(
      self, selector: #selector(stateChanged),
      name: UIApplication.didBecomeActiveNotification, object: nil)
  }

  private func stopObserving() {
    guard observing else { return }
    observing = false
    NotificationCenter.default.removeObserver(self)
  }

  @objc private func stateChanged() {
    updateCover()
  }

  /// Covers the library while it must not appear in a capture: the screen is
  /// being recorded/mirrored, or the app is not frontmost (the app-switcher
  /// snapshot is taken in that window).
  private func updateCover() {
    let mustHide = !allowCapture && (isCaptured || !isFrontmost)
    if mustHide {
      showCover()
    } else {
      removeCover()
    }
  }

  /// The scene's own screen, not the deprecated `UIScreen.main`.
  private var isCaptured: Bool {
    return keyWindow?.windowScene?.screen.isCaptured ?? false
  }

  private var isFrontmost: Bool {
    return UIApplication.shared.applicationState == .active
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

  private func showCover() {
    guard let window = keyWindow else { return }
    if let cover = cover, cover.superview === window {
      window.bringSubviewToFront(cover)
      return
    }
    let view = UIView(frame: window.bounds)
    view.backgroundColor = ScreenCaptureChannel.coverColor
    view.autoresizingMask = [.flexibleWidth, .flexibleHeight]

    let label = UILabel()
    label.text = "Screen capture blocked"
    label.textColor = UIColor(white: 1, alpha: 0.6)
    label.font = .systemFont(ofSize: 15, weight: .medium)
    label.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(label)
    NSLayoutConstraint.activate([
      label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
      label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
    ])

    window.addSubview(view)
    window.bringSubviewToFront(view)
    cover = view
  }

  private func removeCover() {
    cover?.removeFromSuperview()
    cover = nil
  }
}
