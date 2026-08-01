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
    implementation("net.java.dev.jna:jna:5.17.0")
    testImplementation(libs.junit)
}

application {
    mainClass.set("org.matrix.teesimulator.rkahost.cli.HostCli")
    applicationName = "rka-host"
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}

tasks.test {
    dependsOn(tasks.installDist)
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
