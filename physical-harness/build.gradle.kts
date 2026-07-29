import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ktfmt)
}

android {
    namespace = "org.matrix.teesimulator.physicalharness"
    compileSdk = 36
    buildToolsVersion = "36.0.0"

    defaultConfig { minSdk = 36 }

    buildTypes { release { isMinifyEnabled = false } }

    lint { abortOnError = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

kotlin {
    jvmToolchain(21)
    compilerOptions { jvmTarget.set(JvmTarget.JVM_21) }
}

dependencies {
    implementation(project(":two-phone"))
    implementation(libs.bcpkix)
    testImplementation(kotlin("test"))
}

ktfmt { kotlinLangStyle() }
