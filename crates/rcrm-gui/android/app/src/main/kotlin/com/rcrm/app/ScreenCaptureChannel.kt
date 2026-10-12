package com.rcrm.app

import android.app.Activity
import android.view.WindowManager
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * The `rcrm/screen` channel — whether the system may capture this window's
 * pixels (`services/screen_capture.dart`, the app's mobile-only screenshot
 * policy).
 *
 * One window flag carries the whole policy on Android: `FLAG_SECURE` makes a
 * screenshot come out blank, keeps the content out of screen recordings, and
 * hides the task from the recent-apps preview. There is nothing else to do, so
 * this file is the entire native half.
 *
 * The flag is applied at launch ([applyTo], from `MainActivity.onCreate`) before
 * Dart exists, so the default answer is "not capturable" and the window is never
 * briefly photographable while the app starts; Dart then clears it when the
 * stored setting allows capture (`SettingsNotifier.load`).
 *
 * [policy] is remembered process-wide because a window can be recreated (a
 * configuration change the manifest does not absorb) while the policy does not
 * change — the new window has to come back with the choice the user made, not
 * with the launch default.
 */
object ScreenCaptureChannel {
    const val METHOD_CHANNEL = "rcrm/screen"

    /** The choice in force, or null before the app has ever stated one. */
    @Volatile
    private var policy: Boolean? = null

    /** Applies the policy in force to [activity]'s window. */
    fun applyTo(activity: Activity) {
        apply(activity, policy ?: false)
    }

    /** Wires the channel up for [activity]; the caller is the Activity itself. */
    fun register(messenger: BinaryMessenger, activity: Activity) {
        MethodChannel(messenger, METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "setCaptureAllowed" -> {
                    // An absent argument means "do not allow": the safe half of
                    // a malformed call.
                    apply(activity, call.argument<Boolean>("allowed") ?: false)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun apply(activity: Activity, allowCapture: Boolean) {
        policy = allowCapture
        if (allowCapture) {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
