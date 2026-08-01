package com.rcrm.app

import android.content.res.Configuration
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 设置 FLAG_SECURE，禁止屏幕截图并隐藏后台任务预览图
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
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
    }
}
