pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "TEESimulator-RS"

val rkaRuntimeManifest = file("rka-runtime/Cargo.toml")
require(rkaRuntimeManifest.isFile) { "rka-runtime workspace manifest is required" }

include(":stub")

include(":app")

include(":two-phone")

include(":rka-host")

include(":rka-fixture")
