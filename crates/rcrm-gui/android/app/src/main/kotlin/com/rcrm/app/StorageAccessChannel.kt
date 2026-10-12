package com.rcrm.app

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel

/**
 * The `rcrm/storage` channel -- Android's "all files access" layer
 * (`services/storage_access.dart`).
 *
 * RCrm serves the library to the app itself from a local WebDAV server that
 * opens the chosen folders by their REAL filesystem paths, so a per-folder
 * document grant (SAF) is not enough: this process needs raw path access to
 * shared storage. Android never had one API for that, and its three eras are
 * genuinely different -- which is why the status carries the version and the
 * action rather than a single boolean:
 *
 *  * API >= 30 -- all-files access is an APP-OP, not a runtime permission.
 *    There is no dialog to show and `requestPermissions` does nothing for it;
 *    the only way in is the system settings screen
 *    (`ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION`), after which
 *    `Environment.isExternalStorageManager()` answers true. Declaring
 *    `MANAGE_EXTERNAL_STORAGE` in the manifest grants nothing by itself.
 *  * API 23..29 -- an ordinary dangerous runtime permission
 *    (`READ_EXTERNAL_STORAGE`, requested with `WRITE_EXTERNAL_STORAGE`). On
 *    Android 10 specifically this also needs
 *    `android:requestLegacyExternalStorage="true"` in the manifest: 10 is the
 *    release that made scoped storage the default while all-files access did
 *    not exist yet, so the legacy flag plus this grant are the whole route to
 *    raw paths there. (The flag is resolved by the platform in front of us:
 *    10 honours it for apps targeting Q or above, which is why a targetSdk-36
 *    build still needs it on that device; Android 11+ ignores it and uses the
 *    app-op instead.)
 *  * API < 23 -- storage is granted at install and cannot be revoked. There is
 *    nothing to ask, and this is the ONLY case where the app has nothing to do.
 *
 * `request` never holds a `MethodChannel.Result`: it starts the platform flow
 * and answers immediately. Both flows leave the Activity (the settings screen
 * is another task's activity) and a Result kept across that pins a dead
 * Activity -- and on a configuration change answers a channel nobody is
 * listening to. The Dart half re-reads `status` when the app is resumed, which
 * is also the only signal that the user came back from the settings screen.
 *
 * The Activity is captured by the handler the Activity itself registers, in the
 * shape of [ScreenCaptureChannel]; nothing here is held statically except the
 * one note in [KEY_ASKED], which is a fact about the install and not about any
 * Activity.
 */
object StorageAccessChannel {
    const val METHOD_CHANNEL = "rcrm/storage"

    /** Where the "the dialog has been shown at least once" note is kept. */
    private const val PREFS = "rcrm_storage_access"
    private const val KEY_ASKED = "asked_read_external_storage"

    /** Arbitrary; only has to be non-negative and unique inside this Activity. */
    private const val REQUEST_CODE_STORAGE = 0x5354

    /** Wires the channel up for [activity]; the caller is the Activity itself. */
    fun register(messenger: BinaryMessenger, activity: Activity) {
        MethodChannel(messenger, METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "status" -> result.success(status(activity))
                "request" -> result.success(mapOf("launched" to request(activity)))
                else -> result.notImplemented()
            }
        }
    }

    /**
     * Called from `MainActivity.onRequestPermissionsResult`: the storage dialog
     * has been answered, so a later refusal without a rationale really is "for
     * good" and the UI may say so.
     *
     * This is deliberately NOT recorded when the ask is made. Between the
     * request and its result the dialog is on screen and nothing has been
     * decided; treating the ask itself as the record would let a re-read during
     * that window claim Android will not ask again, which is false while the
     * user is looking at the dialog that asks.
     */
    fun onRequestPermissionsResult(context: Context, requestCode: Int) {
        if (requestCode == REQUEST_CODE_STORAGE) markAsked(context)
    }

    private fun status(activity: Activity): Map<String, Any?> {
        // applicationContext: nothing below needs a window, and a status read
        // must not keep an Activity alive.
        val context: Context = activity.applicationContext
        val sdk = Build.VERSION.SDK_INT

        if (sdk < Build.VERSION_CODES.M) {
            return mapOf(
                "sdk" to sdk,
                "granted" to true,
                "action" to "none",
                // Granted at install and never revocable, so nothing may be
                // offered: a button here could not change anything.
                "canAsk" to false,
            )
        }

        if (sdk < Build.VERSION_CODES.R) {
            val read = Manifest.permission.READ_EXTERNAL_STORAGE
            val granted =
                context.checkSelfPermission(read) == PackageManager.PERMISSION_GRANTED
            return mapOf(
                "sdk" to sdk,
                "granted" to granted,
                "action" to "dialog",
                // `shouldShowRequestPermissionRationale` is NOT a record of "has
                // ever asked": the platform answers false for a permission that
                // was never requested as well, which is every fresh install.
                // Read alone it would tell a first-time user that Android will
                // not ask again and send them to Settings for a dialog they
                // never saw, so this app keeps its own note of the asks it has
                // actually completed (onRequestPermissionsResult).
                "canAsk" to (granted || !hasAsked(context) ||
                    activity.shouldShowRequestPermissionRationale(read)),
            )
        }

        return mapOf(
            "sdk" to sdk,
            // The app-op, not the manifest declaration: MANAGE_EXTERNAL_STORAGE
            // can be declared and still be denied by the user.
            "granted" to Environment.isExternalStorageManager(),
            // No dialog exists for this version; the ask is a settings trip.
            "action" to "settings",
            // The settings screen can be opened again whether or not it is
            // granted, so this flow is never "for good".
            "canAsk" to true,
        )
    }

    /** Starts the flow this version needs; false when nothing had to be shown. */
    private fun request(activity: Activity): Boolean {
        val sdk = Build.VERSION.SDK_INT
        if (sdk < Build.VERSION_CODES.M) return false

        if (sdk < Build.VERSION_CODES.R) {
            val read = Manifest.permission.READ_EXTERNAL_STORAGE
            if (activity.applicationContext.checkSelfPermission(read) ==
                PackageManager.PERMISSION_GRANTED
            ) {
                return false
            }
            if (!hasAsked(activity) ||
                activity.shouldShowRequestPermissionRationale(read)
            ) {
                // READ with WRITE, in one dialog and one storage grant: the
                // server only ever reads, but the manifest declares both and
                // these versions grant the pair together.
                activity.requestPermissions(
                    arrayOf(read, Manifest.permission.WRITE_EXTERNAL_STORAGE),
                    REQUEST_CODE_STORAGE,
                )
                return true
            }
            // Refused for good: the platform auto-denies another request, so
            // the app's own settings page -- where the grant can still be given
            // -- IS the ask.
            return openAppDetails(activity)
        }

        if (Environment.isExternalStorageManager()) return false
        return openAllFilesAccess(activity)
    }

    /**
     * The API >= 30 ask, with the fallbacks a version that cannot find either
     * intent still needs. The platform's own reference says of BOTH
     * all-files-access actions that "in some cases, a matching Activity may not
     * exist", and a device that cannot open them must still land the user
     * somewhere the permission can be granted -- its app details page -- rather
     * than crash or do nothing.
     */
    private fun openAllFilesAccess(activity: Activity): Boolean {
        val packageUri = Uri.parse("package:${activity.packageName}")
        val candidates = listOf(
            Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, packageUri),
            Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION),
        )
        for (intent in candidates) {
            try {
                activity.startActivity(intent)
                return true
            } catch (_: ActivityNotFoundException) {
                // Try the next, wider screen.
            } catch (_: Exception) {
                // e.g. SecurityException from a device that hides the screen:
                // never let the ask itself take the app down.
            }
        }
        return openAppDetails(activity)
    }

    /** The last resort, and the API 23..29 "refused for good" ask. */
    private fun openAppDetails(activity: Activity): Boolean {
        return try {
            activity.startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:${activity.packageName}"),
                ),
            )
            true
        } catch (_: Exception) {
            false
        }
    }

    // The note lives in the app's own SharedPreferences: it is one boolean
    // about this install, and it has to outlive the process (the answer decides
    // whether the next launch may offer the dialog at all). It is not a secret
    // and not a setting, so it is not in `services/settings_service.dart`.
    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun hasAsked(context: Context): Boolean = prefs(context).getBoolean(KEY_ASKED, false)

    private fun markAsked(context: Context) {
        prefs(context).edit().putBoolean(KEY_ASKED, true).apply()
    }
}
