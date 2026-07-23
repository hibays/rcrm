plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.rcrm.app"
    compileSdk = 36  // Explicit: fixes AAR metadata checks for ffmpeg_kit etc.
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.rcrm.app"
        minSdk = 24  // ffmpeg_kit_flutter_full requires API 24+
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // Fix duplicate libc++_shared.so from libvlc + ffmpeg-kit
    packaging {
        jniLibs {
            pickFirsts += setOf("lib/arm64-v8a/libc++_shared.so", "lib/armeabi-v7a/libc++_shared.so", "lib/x86/libc++_shared.so", "lib/x86_64/libc++_shared.so")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
