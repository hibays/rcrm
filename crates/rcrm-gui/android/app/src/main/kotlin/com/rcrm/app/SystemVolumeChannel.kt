package com.rcrm.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.media.AudioManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * The `rcrm/volume` channel -- the device's media volume
 * (`services/system_volume.dart`, the mobile-only "System Volume" setting).
 *
 * A phone's hardware keys, its volume panel and every other media app all move
 * ONE stream (`STREAM_MUSIC`). An app that keeps a private volume on top of it
 * is the odd one out, which is why the player drives this stream by default on
 * mobile and stays pinned wide open itself.
 *
 * What crosses this channel is deliberately raw: the app is told the stream's
 * `index`, `min` and `max`, and it sends an `index` back. Every conversion
 * between a percentage and a step -- including the quantisation a stream with a
 * handful of steps causes -- lives in Dart, in one place, unit-tested
 * (`system_volume.dart`). This half only reads and writes the platform's own
 * numbers.
 *
 * The reading is also pushed back to Dart (`onChanged`) whenever the stream
 * changes, whoever changed it: the bar must not keep showing a level the phone
 * is no longer at. TWO mechanisms feed that, because neither is promised --
 * `VOLUME_CHANGED_ACTION` (a broadcast the platform marks "for internal use",
 * hence the literal below and the extras that say WHICH stream moved) and a
 * `ContentObserver` on the settings provider the keys actually write to. Both
 * end in one `push`, which collapses a change they both saw.
 *
 * Nothing here throws into the channel: an unreadable or unsettable device
 * answers with a refusal Dart turns into "keep the player's own volume".
 */
object SystemVolumeChannel {
    const val METHOD_CHANNEL = "rcrm/volume"

    /**
     * `AudioManager.VOLUME_CHANGED_ACTION` -- a `@hide` constant, so it can only
     * be spelled out here. It is a plain (unprotected) broadcast, which is what
     * makes it deliverable to a receiver registered at runtime; the extras name
     * the stream, so another app's ringtone change is filtered out.
     */
    private const val ACTION_VOLUME_CHANGED = "android.media.VOLUME_CHANGED_ACTION"

    /** `AudioManager.EXTRA_VOLUME_STREAM_TYPE` / `_VALUE` -- `@hide` as well. */
    private const val EXTRA_VOLUME_STREAM_TYPE = "android.media.EXTRA_VOLUME_STREAM_TYPE"
    private const val EXTRA_VOLUME_STREAM_VALUE = "android.media.EXTRA_VOLUME_STREAM_VALUE"

    /** Where the last audible level is remembered (see [rememberLastAudible]). */
    private const val PREFS = "rcrm_system_volume"
    private const val KEY_LAST_AUDIBLE = "last_audible_music_index"

    private var channel: MethodChannel? = null
    private var receiver: BroadcastReceiver? = null
    private var observer: ContentObserver? = null

    /** The last reading sent to Dart, so two sources of the same change are one message. */
    private var lastPushed: Map<String, Any>? = null

    /**
     * The application context the receiver is registered against.
     *
     * The application context and not the Activity: the registration outlives
     * one window (a re-created Activity registers again), and following the
     * device's volume is not something that belongs to a window.
     */
    private var appContext: Context? = null

    /** Wires the channel up for [context]'s app; the caller is the Activity. */
    fun attach(context: Context, messenger: BinaryMessenger) {
        val app = context.applicationContext
        appContext = app
        val ch = MethodChannel(messenger, METHOD_CHANNEL)
        ch.setMethodCallHandler { call: MethodCall, result: MethodChannel.Result ->
            when (call.method) {
                // The same reply shape for both directions: the caller always
                // learns what the stream is NOW, never what it asked for.
                "read" -> result.success(reading(app))
                "setIndex" -> {
                    val index = call.argument<Int>("index")
                    if (index != null) apply(app, index)
                    result.success(reading(app))
                }
                else -> result.notImplemented()
            }
        }
        channel = ch
        startReceiver(app)
        startObserver(app)
    }

    /** Drops the broadcast receiver and the settings observer. */
    fun detach() {
        val context = appContext
        val registered = receiver
        val watching = observer
        receiver = null
        observer = null
        channel = null
        appContext = null
        lastPushed = null
        if (context != null && registered != null) {
            try {
                context.unregisterReceiver(registered)
            } catch (_: IllegalArgumentException) {
                // Already gone (the process is on its way out): nothing to undo.
            }
        }
        if (context != null && watching != null) {
            try {
                context.contentResolver.unregisterContentObserver(watching)
            } catch (_: Throwable) {
                // Same: nothing to undo.
            }
        }
    }

    /** The device's media stream, in the platform's own numbers. */
    private fun reading(context: Context): Map<String, Any> {
        val am = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
        // No audio service at all: a well-formed refusal (a stream with no
        // travel and NO `fixed` claim), which Dart reads as "no reading" and
        // answers by keeping the player's own volume. Never a 0..100 claimed out
        // of thin air -- and never `fixed: true`, which is a statement about the
        // device's output that this branch is in no position to make.
        if (am == null) {
            return mapOf(
                "index" to 0,
                "min" to 0,
                "max" to 0,
                "muted" to true,
                "lastAudible" to 0,
                "fixed" to false,
            )
        }
        val min = minIndex(am)
        val max = am.getStreamMaxVolume(AudioManager.STREAM_MUSIC)
        val index = am.getStreamVolume(AudioManager.STREAM_MUSIC)
        return mapOf(
            "index" to index,
            "min" to min,
            "max" to max,
            // Silent either way: at the floor, or muted at a non-zero index by
            // something else. Dart shows both as 0.
            "muted" to (index <= min || isMuted(am)),
            "lastAudible" to rememberLastAudible(context, index, min),
            "fixed" to am.isVolumeFixed,
        )
    }

    /** Moves the media stream to [index], and answers with where it landed. */
    private fun apply(context: Context, index: Int) {
        val am = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager ?: return
        val target = index.coerceIn(minIndex(am), am.getStreamMaxVolume(AudioManager.STREAM_MUSIC))
        try {
            // Flags 0 on purpose: NO `FLAG_SHOW_UI`. The app's own bar is the
            // readout, and the system's volume panel appearing over the video
            // for every frame of a drag is the one thing a bound slider must not
            // do (the hardware keys still show it, which is the platform's own
            // behaviour and not the app's business).
            am.setStreamVolume(AudioManager.STREAM_MUSIC, target, 0)
            if (target > minIndex(am) && isMuted(am)) {
                // A stream muted elsewhere stays silent at a non-zero index.
                // Asking for a level is asking for sound.
                am.adjustStreamVolume(AudioManager.STREAM_MUSIC, AudioManager.ADJUST_UNMUTE, 0)
            }
        } catch (_: SecurityException) {
            // Without MODIFY_AUDIO_SETTINGS the write is refused; the reply is
            // then the unchanged stream, and Dart shows what is really there.
        }
    }

    /** `getStreamMinVolume` is API 28; before that the floor was always 0. */
    private fun minIndex(am: AudioManager): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            am.getStreamMinVolume(AudioManager.STREAM_MUSIC)
        } else {
            0
        }

    private fun isMuted(am: AudioManager): Boolean =
        try {
            am.isStreamMute(AudioManager.STREAM_MUSIC)
        } catch (_: Throwable) {
            false
        }

    /** Called by everything that can notice a volume change. */
    private fun push(context: Context) {
        val reading = reading(context)
        // Two sources can report the same change (a hardware-key press moves the
        // setting AND sends the broadcast), and the observer fires for every
        // system setting there is: one message per real change is enough.
        if (reading == lastPushed) return
        lastPushed = reading
        channel?.invokeMethod("onChanged", reading)
    }

    /**
     * The level this stream was last audible at.
     *
     * Android knows the answer (`AudioManager.getLastAudibleStreamVolume`) and
     * will not tell an app: it is a `@SystemApi` behind `QUERY_AUDIO_STATE`,
     * which is signature|privileged. So the app keeps its own, in its private
     * preferences -- because the question it answers is asked at the START of a
     * session ("the phone is at 0; what should unmute restore?"), and a value
     * that only lived in memory would have nothing to say exactly then.
     *
     * Persisted only when it really changes: this is read once per volume step,
     * and on every settings change the observer above sees.
     */
    private fun rememberLastAudible(context: Context, index: Int, min: Int): Int {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (index > min) {
            // Written only when it really changes: `reading()` runs on every
            // settings change the observer sees, and most of those are not
            // volume at all.
            if (prefs.getInt(KEY_LAST_AUDIBLE, min) != index) {
                prefs.edit().putInt(KEY_LAST_AUDIBLE, index).apply()
            }
            return index
        }
        return prefs.getInt(KEY_LAST_AUDIBLE, min)
    }

    /**
     * Follows the stream, so a change made anywhere but in this app still
     * reaches the bar.
     *
     * Registered for as long as the app is alive (the application context), and
     * once: a re-created Activity attaches again and would otherwise leave two
     * receivers reporting the same change twice.
     */
    private fun startReceiver(context: Context) {
        if (receiver != null) return
        val r =
            object : BroadcastReceiver() {
                override fun onReceive(c: Context?, intent: Intent?) {
                    if (intent == null) return
                    // Which stream moved: the extras are the only way to tell a
                    // media change from a ringtone one.
                    val stream = intent.getIntExtra(EXTRA_VOLUME_STREAM_TYPE, -1)
                    if (stream != AudioManager.STREAM_MUSIC) return
                    if (intent.getIntExtra(EXTRA_VOLUME_STREAM_VALUE, -1) < 0) return
                    val app = appContext ?: return
                    push(app)
                }
            }
        val filter = IntentFilter(ACTION_VOLUME_CHANGED)
        // Target SDK 36: a receiver registered for a broadcast the framework
        // does not recognise as protected must SAY whether it is exported, or
        // `registerReceiver` throws. It is not exported -- only the system sends
        // this, and the system is exempt from that check.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            context.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(r, filter)
        }
        receiver = r
    }

    /**
     * The second way a change gets noticed, because the first one is not
     * promised to anyone.
     *
     * `VOLUME_CHANGED_ACTION` is marked "for internal platform use" by the
     * platform, so a device that does not deliver it to apps would leave the bar
     * describing a volume the phone is no longer at. The settings provider is
     * public API, and it is where the volume the keys move actually lives - so
     * it is watched too, and both paths end in the same [push] (which collapses
     * the duplicate).
     *
     * The observer hears EVERY system setting, including the screen brightness
     * this app itself writes once per frame during a brightness swipe, so the
     * changed key is filtered: only a volume key is worth re-reading.
     */
    private fun startObserver(context: Context) {
        if (observer != null) return
        val o =
            object : ContentObserver(Handler(Looper.getMainLooper())) {
                override fun onChange(selfChange: Boolean, uri: Uri?) {
                    val key = uri?.lastPathSegment ?: return
                    if (!key.contains("volume")) return
                    val app = appContext ?: return
                    push(app)
                }
            }
        context.contentResolver.registerContentObserver(
            Settings.System.CONTENT_URI,
            true,
            o,
        )
        observer = o
    }
}
