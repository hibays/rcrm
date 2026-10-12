package com.rcrm.app

import android.content.res.Configuration
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // The screenshot policy, before Dart exists: the launch default is NOT
        // capturable, and the stored choice lifts it a moment later
        // (`ScreenCaptureChannel`, `services/screen_capture.dart`).
        ScreenCaptureChannel.applyTo(this)
    }

    override fun onDestroy() {
        super.onDestroy()
        // Android frequently keeps the process cached after the Activity dies.
        // That surviving process carries secrets (page-locked keys, accepted
        // keys) and native state (Rust server threads, libmpv contexts) into
        // the next session — the password prompt gets skipped and orphaned mpv
        // contexts crash inline video previews on relaunch. Since the password
        // is entered fresh every launch anyway, die with the Activity so every
        // launch is a clean cold start. Only when the Activity is truly
        // finishing: a non-finishing destroy (e.g. "Don't keep activities")
        // must keep the process so the user's current session survives.
        // (Swiped-away-from-recents needs no handling: the OS tears the task
        // down and reaps the process itself.)
        if (isFinishing) killOnExit()
    }

    private fun killOnExit() {
        try {
            android.os.Process.killProcess(android.os.Process.myPid())
        } catch (_: Throwable) {
            // Best-effort: if killing fails the process just lingers and the
            // OS reclaims it later.
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // TV detection: the receiver screen is the default home on Android TV.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "rcrm/tv")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "isTv" -> {
                        val mode = resources.configuration.uiMode and
                            Configuration.UI_MODE_TYPE_MASK
                        result.success(mode == Configuration.UI_MODE_TYPE_TELEVISION)
                    }
                    else -> result.notImplemented()
                }
            }
        // Clean app exit ("press back again to exit" second press).
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "rcrm/app")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "exitApp" -> {
                        finishAndRemoveTask()
                        android.os.Process.killProcess(android.os.Process.myPid())
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
        // Screenshot policy, the Dart half of the flag applied in onCreate.
        ScreenCaptureChannel.register(flutterEngine.dartExecutor.binaryMessenger, this)
        // Storage access: the library is read by real filesystem path, so the
        // app needs all-files access on Android 11+ and the storage grant (plus
        // the manifest's legacy-storage flag) on Android 6-10.
        StorageAccessChannel.register(flutterEngine.dartExecutor.binaryMessenger, this)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        // Plugins get this first (the engine's own permission plumbing).
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        // The storage dialog has been answered, which is the one fact about
        // this permission the app cannot read back from the platform
        // (`StorageAccessChannel`).
        StorageAccessChannel.onRequestPermissionsResult(this, requestCode)
    }
}
