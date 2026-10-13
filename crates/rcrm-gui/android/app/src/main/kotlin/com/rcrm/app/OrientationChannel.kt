package com.rcrm.app

import android.app.Activity
import android.content.pm.ActivityInfo
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel

/**
 * The `rcrm/orientation` channel -- the one orientation the framework cannot ask
 * for (`services/screen_orientation.dart`, the "follow the phone" strategy).
 *
 * `SystemChrome.setPreferredOrientations` carries a LIST of orientations, and the
 * Flutter engine turns that list into a single `SCREEN_ORIENTATION_*` value from a
 * fixed table: all four become `FULL_USER`, whose own documentation is "Respect
 * the user's sensor-based rotation preference". So an app that wants the sensor to
 * win over the user's rotation lock -- `FULL_SENSOR`, "Ignores user's setting to
 * turn off sensor-based rotation" -- has to ask the Activity itself, which is
 * all this file does.
 *
 * One method, no state, nothing reported back: every other strategy, and leaving
 * fullscreen at all, goes back through `SystemChrome`, which is what restores the
 * app's own direction.
 */
object OrientationChannel {
    const val METHOD_CHANNEL = "rcrm/orientation"

    /** Wires the channel up for [activity]; the caller is the Activity itself. */
    fun register(messenger: BinaryMessenger, activity: Activity) {
        MethodChannel(messenger, METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "follow" -> {
                    // Deliberately NOT wrapped in a preference check: this is the
                    // user asking, mid-video, for the picture to follow the phone.
                    // `setRequestedOrientation` is the same call the framework's
                    // own `setPreferredOrientations` ends in -- this just names a
                    // value its table cannot reach.
                    activity.requestedOrientation =
                        ActivityInfo.SCREEN_ORIENTATION_FULL_SENSOR
                    result.success(null)
                }
                "release" -> {
                    // Nothing to undo HERE: the sensor request above is just a
                    // value of the activity's orientation property, and the
                    // caller's next `setPreferredOrientations` (all four, on every
                    // strategy change and on the way out) writes over it. iOS needs
                    // a real stop -- it keeps observers -- which is why the method
                    // exists at all.
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }
}
