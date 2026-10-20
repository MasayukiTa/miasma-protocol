plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}



// Keep the WebView surface on the same canonical web/ tree as the standalone PWA.
// The generated directory is under build/ so Android packaging never requires a
// second checked-in copy that can drift from the browser release.
val canonicalWebDir = rootProject.projectDir.parentFile.resolve("web")
val generatedWebAssetsDir = layout.buildDirectory.dir("generated/miasmaWebAssets")
val syncMiasmaWebAssets by tasks.registering(org.gradle.api.tasks.Sync::class) {
    from(canonicalWebDir) {
        exclude("tests/**")
        exclude("pkg/.gitignore")
        exclude("pkg/*.d.ts")
        exclude("pkg/package.json")
    }
    into(generatedWebAssetsDir.map { it.dir("web") })
}

val releaseVersionCode = System.getenv("MIASMA_ANDROID_VERSION_CODE")?.toIntOrNull() ?: 1
val releaseVersionName = System.getenv("MIASMA_ANDROID_VERSION_NAME")?.takeIf { it.isNotBlank() } ?: "0.3.2"
val releaseKeystore = System.getenv("MIASMA_ANDROID_KEYSTORE")
val releaseStorePassword = System.getenv("MIASMA_ANDROID_STORE_PASSWORD")
val releaseKeyAlias = System.getenv("MIASMA_ANDROID_KEY_ALIAS")
val releaseKeyPassword = System.getenv("MIASMA_ANDROID_KEY_PASSWORD")
val hasReleaseSigning = listOf(
    releaseKeystore,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

android {
    namespace   = "dev.miasma"
    compileSdk  = 36
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "dev.miasma"
        minSdk        = 26          // Android 8 — QUIC support baseline
        targetSdk     = 36
        versionCode   = releaseVersionCode
        versionName   = releaseVersionName
        ndk {
            // Keep the packaged JNA ABI set identical to the Rust cdylibs we build.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(releaseKeystore!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }

    // JNI libs produced by `cargo ndk … -o android/app/src/main/jniLibs`
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")
    sourceSets["main"].assets.srcDir(generatedWebAssetsDir)
    packaging {
        jniLibs {
            // AGP 8.11 then stores native libraries with modern page alignment.
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.lifecycle.runtime.ktx)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)

    // UniFFI Kotlin bindings call the Rust cdylib through JNA. Android needs the AAR artifact.
    implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")

    // Compose (via BOM so all versions stay in sync)
    val composeBom = platform(libs.compose.bom)
    implementation(composeBom)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.material3)
    implementation(libs.compose.icons.extended)
    implementation(libs.compose.navigation)
    implementation(libs.material.components)
    debugImplementation(libs.compose.ui.tooling)
    implementation(libs.compose.ui.tooling.preview)

    // Serves the bundled web client over https://appassets.androidplatform.net/ in the WebView
    implementation(libs.androidx.webkit)

    // QR code
    implementation(libs.zxing.embedded)
}

// Android assets must exist before resource merging for every build variant.
tasks.named("preBuild").configure {
    dependsOn(syncMiasmaWebAssets)
}
