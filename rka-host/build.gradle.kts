import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    application
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktfmt)
}

ktfmt { kotlinLangStyle() }

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_21) }
    jvmToolchain(21)
}

dependencies {
    implementation(project(":two-phone"))
    testImplementation(libs.junit)
}

application {
    mainClass.set("org.matrix.teesimulator.rkahost.CandidateIdentityGateCli")
    applicationName = "rka-host"
}
