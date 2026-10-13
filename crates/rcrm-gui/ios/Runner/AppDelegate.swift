import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  /// Held for the app's lifetime: it owns the capture observers
  /// (`ScreenCaptureChannel.swift`).
  private var screenCapture: ScreenCaptureChannel?

  /// Held for the app's lifetime: it owns the output-volume observer
  /// (`SystemVolumeChannel.swift`).
  private var systemVolume: SystemVolumeChannel?

  /// Held for the app's lifetime: it owns the device-orientation observers
  /// (`OrientationChannel.swift`).
  private var orientation: OrientationChannel?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    // The app's own channels sit next to the generated plugin registrations —
    // the screenshot policy is one of them (`ScreenCaptureChannel.swift`).
    screenCapture = ScreenCaptureChannel.register(
      with: engineBridge.pluginRegistry.registrar(forPlugin: "RcrmScreenCapture"))
    // The device's output volume, which is what the player's volume control
    // moves on mobile.
    systemVolume = SystemVolumeChannel.register(
      with: engineBridge.pluginRegistry.registrar(forPlugin: "RcrmSystemVolume"))
    // The fullscreen player's "follow how the phone is held" strategy, which on
    // iOS needs the hardware posture and an explicit geometry request.
    orientation = OrientationChannel.register(
      with: engineBridge.pluginRegistry.registrar(forPlugin: "RcrmOrientation"))
  }
}
