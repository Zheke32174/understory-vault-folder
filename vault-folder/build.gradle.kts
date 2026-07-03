plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.vaultfolder"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.vaultfolder"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-skeleton"
        resourceConfigurations += listOf("en")
        base.archivesName = "vault-folder"
    }

    buildTypes {
        debug {
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            isMinifyEnabled = false
            isShrinkResources = false
        }
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    flavorDimensions += "channel"
    productFlavors {
        create("prod") {
            dimension = "channel"
        }
        create("eng") {
            dimension = "channel"
            applicationIdSuffix = ".eng"
            versionNameSuffix = "-eng"
        }
    }
}

dependencies {
    implementation(project(":common-security"))
    // Recovery-envelope hand-off (VaultRecoveryEnvelope) + BackupAdapter for
    // the shared vault-recovery contract (§4). Transitively re-exposes
    // common-security, so the single explicit dep above is retained for clarity.
    implementation(project(":common-backup"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")

    // BiometricPrompt with DEVICE_CREDENTIAL fallback for unlock.
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // See passgen/build.gradle.kts for the rationale: override fragment
    // 1.2.5 (transitively pinned by biometric:1.2.0-alpha05) which has
    // the legacy 16-bit requestCode check that breaks
    // rememberLauncherForActivityResult.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    // Fragment is required because BiometricPrompt needs FragmentActivity.
    implementation("androidx.fragment:fragment-ktx:1.8.5")
}
