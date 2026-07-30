import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktfmt)
}

ktfmt { kotlinLangStyle() }

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_21) }
    jvmToolchain(21)
}

dependencies { testImplementation(libs.junit) }
