import java.io.ByteArrayInputStream
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ktfmt)
}

android {
    namespace = "org.matrix.teesimulator.rkafixture"
    compileSdk = 36
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "org.matrix.teesimulator.rkafixture"
        minSdk = 36
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

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
    implementation(project(":physical-harness"))
    implementation(project(":two-phone"))
    testImplementation(kotlin("test"))
}

val fixtureSigningEnvironment =
    mapOf(
        "TEESIM_FIXTURE_KEYSTORE" to System.getenv("TEESIM_FIXTURE_KEYSTORE").orEmpty(),
        "TEESIM_FIXTURE_STORE_PASSWORD_FILE" to
            System.getenv("TEESIM_FIXTURE_STORE_PASSWORD_FILE").orEmpty(),
        "TEESIM_FIXTURE_KEY_ALIAS" to System.getenv("TEESIM_FIXTURE_KEY_ALIAS").orEmpty(),
        "TEESIM_FIXTURE_KEY_PASSWORD_FILE" to
            System.getenv("TEESIM_FIXTURE_KEY_PASSWORD_FILE").orEmpty(),
    )
val fixtureUnsignedApk =
    layout.buildDirectory.file("outputs/apk/release/rka-fixture-release-unsigned.apk")
val fixtureSignedApk = layout.buildDirectory.file("outputs/apk/release/rka-fixture-release.apk")
val fixtureBuildTools = android.sdkDirectory.resolve("build-tools/${android.buildToolsVersion}")
val signFixtureReleaseApk =
    tasks.register<Exec>("signFixtureReleaseApk") {
        dependsOn("packageRelease")
        inputs.file(fixtureUnsignedApk)
        outputs.file(fixtureSignedApk)
        outputs.upToDateWhen { false }
        executable(rootProject.file("scripts/sign-fixture-release-apk.sh"))
        args(
            "--input",
            fixtureUnsignedApk.get().asFile.absolutePath,
            "--output",
            fixtureSignedApk.get().asFile.absolutePath,
            "--apksigner",
            fixtureBuildTools.resolve("apksigner").absolutePath,
            "--zipalign",
            fixtureBuildTools.resolve("zipalign").absolutePath,
        )
        environment(fixtureSigningEnvironment)
        standardInput = ByteArrayInputStream(ByteArray(0))
    }

tasks.matching { it.name == "assembleRelease" }.configureEach { dependsOn(signFixtureReleaseApk) }

ktfmt { kotlinLangStyle() }
