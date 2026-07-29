plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktfmt)
}

kotlin { jvmToolchain(21) }

dependencies {
    testImplementation(kotlin("test"))
    testImplementation(libs.bcpkix)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}

ktfmt { kotlinLangStyle() }
