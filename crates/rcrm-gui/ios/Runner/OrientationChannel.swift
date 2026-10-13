import Flutter
import UIKit

/// The `rcrm/orientation` channel — the iOS half of the "follow how the phone is
/// held" strategy (`services/screen_orientation.dart`).
///
/// iOS has no `SCREEN_ORIENTATION_FULL_SENSOR`, and `SystemChrome
/// .setPreferredOrientations` can only ever NARROW the app's supported mask — a
/// mask cannot make the interface rotate while the user's rotation lock is on,
/// which is exactly what this strategy is for. So the app does it the two ways
/// iOS offers:
///
///  * `UIDevice.current.orientation` is the HARDWARE posture (accelerometer), and
///    it is unaffected by the rotation lock — that is the "how the phone is held"
///    this reads, through `orientationDidChangeNotification`;
///  * the interface is then moved there explicitly: `requestGeometryUpdate` on
///    iOS 16+ (public API, and the reason Apple added it), or the long-standing
///    `setValue(_:forKey: "orientation")` + `attemptRotationToDeviceOrientation`
///    pair before that.
///
/// The mask still has to allow the orientation being asked for, so Dart sends
/// `setPreferredOrientations` for all four BEFORE asking to follow (that order is
/// required, and the Dart side documents it). Face-up/face-down reports carry no
/// direction and are ignored: the screen keeps what it has rather than guessing.
///
/// `release` stops all of it. Leaving fullscreen, leaving the player, or picking
/// any other strategy goes back through `SystemChrome`, and a sensor that kept
/// forcing a geometry after that would fight it.
///
/// The device reports are NOT the interface orientation: `UIDeviceOrientation
/// .landscapeLeft` means the phone was turned so that the home button is on the
/// RIGHT, which the interface calls `landscapeRight`. The mapping below inverts
/// them, as every iOS app that reads this sensor has to.
final class OrientationChannel: NSObject {
  static let methodChannelName = "rcrm/orientation"

  private var channel: FlutterMethodChannel?
  private var following = false

  /// Wires the channel up. The caller (the app delegate) holds the returned
  /// object for the app's lifetime.
  static func register(with registrar: FlutterPluginRegistrar) -> OrientationChannel {
    let instance = OrientationChannel()
    let channel = FlutterMethodChannel(
      name: methodChannelName, binaryMessenger: registrar.messenger())
    instance.channel = channel
    // `[weak instance]`: the channel retains this closure and the instance
    // retains the channel, so a strong capture would keep this object — and its
    // device-orientation observers — alive for the whole process.
    channel.setMethodCallHandler { [weak instance] call, result in
      guard let instance = instance else {
        result(FlutterMethodNotImplemented)
        return
      }
      switch call.method {
      case "follow":
        instance.startFollowing()
        result(nil)
      case "release":
        instance.stopFollowing()
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    return instance
  }

  private func startFollowing() {
    guard !following else {
      // Already following: apply the posture the phone is in right now, which is
      // what the caller means by asking again.
      apply(deviceOrientation: UIDevice.current.orientation)
      return
    }
    following = true
    NotificationCenter.default.addObserver(
      self, selector: #selector(orientationChanged),
      name: UIDevice.orientationDidChangeNotification, object: nil)
    UIDevice.current.beginGeneratingDeviceOrientationNotifications()
    apply(deviceOrientation: UIDevice.current.orientation)
  }

  private func stopFollowing() {
    guard following else { return }
    following = false
    NotificationCenter.default.removeObserver(
      self, name: UIDevice.orientationDidChangeNotification, object: nil)
    UIDevice.current.endGeneratingDeviceOrientationNotifications()
  }

  @objc private func orientationChanged() {
    apply(deviceOrientation: UIDevice.current.orientation)
  }

  /// Moves the interface to where the phone is held, or does nothing at all.
  private func apply(deviceOrientation: UIDeviceOrientation) {
    guard following else { return }
    let mask: UIInterfaceOrientationMask
    let legacy: UIInterfaceOrientation
    switch deviceOrientation {
    case .portrait:
      mask = .portrait
      legacy = .portrait
    case .portraitUpsideDown:
      mask = .portraitUpsideDown
      legacy = .portraitUpsideDown
    case .landscapeLeft:
      // The phone's landscapeLeft is the interface's landscapeRight.
      mask = .landscapeRight
      legacy = .landscapeRight
    case .landscapeRight:
      mask = .landscapeLeft
      legacy = .landscapeLeft
    default:
      // faceUp, faceDown, unknown: no direction to follow.
      return
    }

    guard let scene = keyWindow?.windowScene else { return }
    if #available(iOS 16.0, *) {
      // The system refuses when the app is not frontmost, or when the mask does
      // not allow the orientation — in which case the screen keeps what it has,
      // which is the honest outcome of "the platform said no".
      scene.requestGeometryUpdate(.iOS(interfaceOrientations: mask)) { _ in }
    } else {
      // iOS 13–15: the pair every app used before the API above existed.
      //
      // ACCEPTED RISK, stated here rather than buried: this is undocumented API,
      // so it can break on an OS update and it does not carry the review
      // scrutiny a documented call does. There is no public pre-16 alternative —
      // `setPreferredOrientations` can only narrow the mask, and a narrower mask
      // does not rotate the interface while the user's rotation lock is on, which
      // is the whole point of this channel. The alternatives are product
      // decisions this file does not make on its own: raise the deployment target
      // to 16 (iOS 13–15 then get the system's own behaviour, no `follow`), or
      // keep `device` off the panel below 16.
      UIDevice.current.setValue(legacy.rawValue, forKey: "orientation")
      UIViewController.attemptRotationToDeviceOrientation()
    }
  }

  /// The scene's own key window, not the deprecated `UIScreen.main`.
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

  deinit {
    stopFollowing()
  }
}
