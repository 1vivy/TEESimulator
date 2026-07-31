import com.android.build.api.artifact.SingleArtifact
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.zip.ZipFile
import javax.inject.Inject
import org.apache.commons.compress.archivers.zip.ZipFile as CommonsZipFile
import org.gradle.process.ExecOperations
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ktfmt)
}

ktfmt { kotlinLangStyle() }

// Helper class to get access to the ExecOperations service
abstract class GitExecutor @Inject constructor(private val execOperations: ExecOperations) {
    fun execute(command: String, currentWorkingDir: File): String {
        val byteOut = ByteArrayOutputStream()
        execOperations.exec {
            workingDir = currentWorkingDir
            commandLine = command.split("\\s".toRegex())
            standardOutput = byteOut
        }
        return String(byteOut.toByteArray()).trim()
    }
}

// Instantiate the helper class using Gradle's object factory
val gitExecutor = objects.newInstance(GitExecutor::class.java)

// versionCode = git commit count + floor offset. The 2026-07-08 public-release
// history scrub (0f1143a) rewrote history and dropped the raw commit count below
// the build number already shipped to testers (298), so post-scrub counts read as
// downgrades. The floor offset lifts versionCode back above that peak and keeps it
// monotonic across the rewrite; each later commit still bumps it by one.
val versionCodeFloorOffset = 5
val gitCommitCount =
    gitExecutor.execute("git rev-list HEAD --count", rootDir).toInt() + versionCodeFloorOffset
val gitCommitHash = gitExecutor.execute("git rev-parse --verify --short HEAD", rootDir)
val gitCommitSha = gitExecutor.execute("git rev-parse --verify HEAD", rootDir)
val verName = "v6.0.1"

android {
    namespace = "org.matrix.TEESimulator"
    compileSdk = 36
    ndkVersion = "27.3.13750724"
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "org.matrix.TEESimulator"
        minSdk = 29
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = verName
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures { buildConfig = true }
    testOptions { unitTests.isReturnDefaultValues = true }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_21) } }

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    implementation(libs.bcpkix)
    testImplementation(project(":stub"))
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
}

// --- Rust native cert gen build task ---
val buildRustCertgen by
    tasks.registering(Exec::class) {
        group = "TEESimulator-RS Native Build"
        description = "Builds libcertgen.so via cargo-ndk for arm64-v8a."

        workingDir = rootProject.projectDir.resolve("native-certgen")

        commandLine(
            rootProject.projectDir.resolve("scripts/rka-toolchain.sh"),
            "cargo",
            "ndk",
            "-t",
            "arm64-v8a",
            "-o",
            rootProject.projectDir.resolve("app/src/main/jniLibs").absolutePath,
            "build",
            "--release",
        )

        inputs.dir(rootProject.projectDir.resolve("native-certgen/src"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.toml"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.lock"))
        outputs.dir(rootProject.projectDir.resolve("app/src/main/jniLibs"))

        environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
    }

val rkaRuntimeAbi = providers.gradleProperty("rkaRuntimeAbi").orElse("arm64-v8a")
val rkaRuntimeTargetDir =
    providers.environmentVariable("CARGO_TARGET_DIR").orElse(
        rootProject.layout.projectDirectory.dir(".omo/runtime/cargo-target").asFile.absolutePath
    )
val rkaRuntimeStageDir = layout.buildDirectory.dir("rka-runtime/arm64-v8a")

val verifyRkaRuntimeAbis by
    tasks.registering {
        group = "TEESimulator-RS Native Build"
        description = "Rejects unsupported RKA runtime ABIs before any sidecar build."

        inputs.property("rkaRuntimeAbi", rkaRuntimeAbi)
        doLast {
            val selectedAbi = rkaRuntimeAbi.get()
            require(selectedAbi == "arm64-v8a") {
                "Unsupported RKA runtime ABI '$selectedAbi'; only arm64-v8a is supported."
            }
        }
    }

val buildRkaRuntimeArm64 by
    tasks.registering(Exec::class) {
        group = "TEESimulator-RS Native Build"
        description = "Builds the separate rka-sidecar executable for Android arm64."
        dependsOn(verifyRkaRuntimeAbis)

        workingDir = rootProject.projectDir.resolve("rka-runtime")
        commandLine(
            rootProject.projectDir.resolve("scripts/rka-toolchain.sh"),
            "cargo",
            "ndk",
            "-t",
            "arm64-v8a",
            "build",
            "--package",
            "rka-sidecar",
            "--release",
        )
        inputs.dir(rootProject.projectDir.resolve("rka-runtime/crates"))
        inputs.file(rootProject.projectDir.resolve("rka-runtime/Cargo.toml"))
        inputs.file(rootProject.projectDir.resolve("rka-runtime/Cargo.lock"))
        inputs.file(rootProject.projectDir.resolve("rka-runtime/rust-toolchain.toml"))
        outputs.file(
            rkaRuntimeTargetDir.map {
                file("$it/aarch64-linux-android/release/rka-sidecar")
            }
        )
    }

val stageRkaRuntimeArm64 by
    tasks.registering(Sync::class) {
        group = "TEESimulator-RS Native Build"
        description = "Stages rka-sidecar separately from native-certgen."
        dependsOn(buildRkaRuntimeArm64)

        from(
            rkaRuntimeTargetDir.map {
                file("$it/aarch64-linux-android/release/rka-sidecar")
            }
        )
        into(rkaRuntimeStageDir)
        rename { "rka-sidecar" }
    }

// AGP auto-detects jniLibs/ as an input to mergeJniLibFolders — wire the dependency
tasks.configureEach {
    if (name.endsWith("JniLibFolders") && name.startsWith("merge")) {
        dependsOn(buildRustCertgen)
    }
    if (name == "assembleRelease") {
        dependsOn(stageRkaRuntimeArm64)
    }
}

// Auto-rewrite module/update.json on every packaging build so versionCode and
// zipUrl track gitCommitCount automatically, matching module.prop.
val refreshUpdateJson by
    tasks.registering {
        group = "TEESimulator-RS Module Packaging"
        description = "Rewrite module/update.json to match current verName and gitCommitCount."

        val updateJsonFile = rootProject.projectDir.resolve("module/update.json")
        val capturedVerName = verName
        val capturedCount = gitCommitCount

        inputs.property("verName", capturedVerName)
        inputs.property("gitCommitCount", capturedCount)
        outputs.file(updateJsonFile)

        doLast {
            val fullVer = "$capturedVerName-$capturedCount"
            updateJsonFile.writeText(
                """{
  "version": "$fullVer",
  "versionCode": $capturedCount,
  "zipUrl": "https://github.com/Enginex0/TEESimulator-RS/releases/download/$fullVer/TEESimulator-RS-$fullVer-Release.zip",
  "changelog": "https://raw.githubusercontent.com/Enginex0/TEESimulator-RS/main/module/changelog.md"
}
"""
            )
        }
    }

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalized = variant.name.replaceFirstChar { it.uppercase() }
        val isDebug = variant.buildType == "debug"

        // --- Define output locations and file names ---
        // Stage all files in a temporary directory inside 'build' before zipping
        val tempModuleDir = project.layout.buildDirectory.dir("module/${variant.name}")
        val zipFileName = "TEESimulator-RS-$verName-$gitCommitCount-$capitalized.zip"

        // Task 1: Prepare all module files in the temporary build directory.
        // Using Sync ensures that stale files from previous runs are removed.
        val prepareModuleFilesTask =
            tasks.register<Sync>("prepareModuleFiles${capitalized}") {
                group = "TEESimulator-RS Module Packaging"
                description = "Prepares all files for the ${variant.name} module zip."

                if (isDebug) {
                    dependsOn("package${capitalized}")
                } else {
                    dependsOn("minify${capitalized}WithR8")
                    dependsOn("strip${capitalized}DebugSymbols")
                }
                dependsOn(buildRustCertgen)
                dependsOn(stageRkaRuntimeArm64)

                if (isDebug) {
                    from(variant.artifacts.get(SingleArtifact.APK)) {
                        include("*.apk")
                        rename { "service.apk" }
                    }
                } else {
                    from(
                        project.layout.buildDirectory.dir(
                            "intermediates/dex/${variant.name}/minify${capitalized}WithR8"
                        )
                    ) {
                        include("classes.dex")
                    }
                }

                val nativeLibsDir =
                    if (isDebug) {
                        "intermediates/merged_native_libs/${variant.name}/merge${capitalized}NativeLibs/out/lib"
                    } else {
                        "intermediates/stripped_native_libs/${variant.name}/strip${capitalized}DebugSymbols/out/lib"
                    }
                from(project.layout.buildDirectory.dir(nativeLibsDir)) {
                    into("lib")
                    include(
                        "**/libinject.so",
                        "**/libTEESimulator.so",
                        "**/libsupervisor.so",
                        "**/libcertgen.so",
                    )
                }
                from(rkaRuntimeStageDir) { include("rka-sidecar") }

                val sourceModuleDir = rootProject.projectDir.resolve("module")
                from(sourceModuleDir) {
                    include(
                        "daemon",
                        "module.prop",
                        "rka-control.sh",
                        "rka-paths.sh",
                        "rka-profile.schema",
                        "rka-role.conf",
                        "rka-runtime.manifest",
                        "rka-supervisor.sh",
                        "sepolicy.rule",
                        "service.sh",
                        "uninstall.sh",
                    )
                    exclude("module.prop")
                }
                from(sourceModuleDir.resolve("webroot")) {
                    into("webroot")
                    include("**/*")
                }
                from(rootProject.projectDir.resolve("NOTICE")) { into("licenses") }
                from(rootProject.projectDir.resolve("LICENSE")) { into("licenses") }

                // Copy and filter the module.prop template separately.
                from(sourceModuleDir) {
                    include("module.prop")
                    expand(
                        "REPLACEMEVERCODE" to gitCommitCount.toString(),
                        "REPLACEMEVER" to "$verName-$gitCommitCount",
                    )
                }

                into(tempModuleDir)
                filePermissions { unix("0644") }
                filesMatching("daemon") { filePermissions { unix("0755") } }
                filesMatching("rka-control.sh") { filePermissions { unix("0755") } }
                filesMatching("rka-paths.sh") { filePermissions { unix("0755") } }
                filesMatching("rka-supervisor.sh") { filePermissions { unix("0755") } }
                filesMatching("service.sh") { filePermissions { unix("0755") } }
                filesMatching("uninstall.sh") { filePermissions { unix("0755") } }
                filesMatching("rka-sidecar") { filePermissions { unix("0755") } }

                doLast {
                    val stageDirectory = tempModuleDir.get().asFile
                    val executableEntries =
                        setOf(
                            "daemon",
                            "rka-control.sh",
                            "rka-paths.sh",
                            "rka-sidecar",
                            "rka-supervisor.sh",
                            "service.sh",
                            "uninstall.sh",
                        )
                    val artifactEntries =
                        stageDirectory
                            .walkTopDown()
                            .filter(File::isFile)
                            .map { it.relativeTo(stageDirectory).invariantSeparatorsPath }
                            .filterNot { it.startsWith("META-INF/") }
                            .sorted()
                            .toList()
                    artifactEntries.forEach { entry ->
                        val mode = if (entry in executableEntries) "rwxr-xr-x" else "rw-r--r--"
                        Files.setPosixFilePermissions(
                            stageDirectory.resolve(entry).toPath(),
                            PosixFilePermissions.fromString(mode),
                        )
                    }
                    val digest = MessageDigest.getInstance("SHA-256")
                    fun digestFile(file: File): String {
                        digest.reset()
                        file.inputStream().use { input ->
                            val buffer = ByteArray(8192)
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                digest.update(buffer, 0, count)
                            }
                        }
                        return digest.digest().joinToString("") { "%02x".format(it) }
                    }
                    val metadataDirectory = stageDirectory.resolve("META-INF")
                    metadataDirectory.mkdirs()
                    val artifactManifest = metadataDirectory.resolve("rka-artifacts.sha256")
                    artifactManifest.writeText(
                        artifactEntries.joinToString("\n") { entry ->
                            "${digestFile(stageDirectory.resolve(entry))}  $entry"
                        } + "\n",
                    )
                    val sourceEntries =
                        listOf(
                            "NOTICE",
                            "LICENSE",
                            "module/daemon",
                            "module/module.prop",
                            "module/rka-control.sh",
                            "module/rka-paths.sh",
                            "module/rka-profile.schema",
                            "module/rka-role.conf",
                            "module/rka-runtime.manifest",
                            "module/rka-supervisor.sh",
                            "module/sepolicy.rule",
                            "module/service.sh",
                            "module/uninstall.sh",
                        ) +
                            sourceModuleDir.resolve("webroot").walkTopDown().filter(File::isFile).map {
                                it.relativeTo(rootProject.projectDir).invariantSeparatorsPath
                            }.toList().sorted()
                    val sourceManifest = metadataDirectory.resolve("rka-source.sha256")
                    sourceManifest.writeText(
                        "commit=$gitCommitSha\n" +
                            sourceEntries.joinToString("\n") { entry ->
                                "${digestFile(rootProject.projectDir.resolve(entry))}  $entry"
                            } + "\n",
                    )
                    listOf(artifactManifest, sourceManifest).forEach {
                        Files.setPosixFilePermissions(
                            it.toPath(),
                            PosixFilePermissions.fromString("rw-r--r--"),
                        )
                    }
                }
            }

        // Task 2: Zip the prepared files from the temporary directory.
        val zipTask =
            tasks.register<Zip>("zip${capitalized}") {
                group = "TEESimulator-RS Module Packaging"
                description = "Creates the flashable zip for the ${variant.name} module."
                dependsOn(prepareModuleFilesTask)

                archiveFileName.set(zipFileName)
                destinationDirectory.set(project.rootDir.resolve("out"))
                from(tempModuleDir) {
                    include(
                        "daemon",
                        "rka-control.sh",
                        "rka-paths.sh",
                        "rka-sidecar",
                        "rka-supervisor.sh",
                        "service.sh",
                        "uninstall.sh",
                    )
                    filePermissions { unix("0755") }
                }
                from(tempModuleDir) {
                    exclude(
                        "daemon",
                        "rka-control.sh",
                        "rka-paths.sh",
                        "rka-sidecar",
                        "rka-supervisor.sh",
                        "service.sh",
                        "uninstall.sh",
                    )
                    filePermissions { unix("0644") }
                }
                isPreserveFileTimestamps = false
                isReproducibleFileOrder = true
                if (!isDebug) {
                    doLast {
                        val archive = archiveFile.get().asFile
                        val digest = MessageDigest.getInstance("SHA-256")
                        val hash = archive.inputStream().use { input ->
                            val buffer = ByteArray(8192)
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                digest.update(buffer, 0, count)
                            }
                            digest.digest().joinToString("") { "%02x".format(it) }
                        }
                        rootProject.layout.buildDirectory
                            .file("rka-release.sha256")
                            .get()
                            .asFile
                            .writeText("$hash  out/${archive.name}\n")
                    }
                }
            }

        // Task 3: A helper function to create installation tasks for different root providers.
        fun createInstallTasks(rootProvider: String, installCli: String) {
            val pushTask =
                tasks.register<Exec>("push${rootProvider}Module${capitalized}") {
                    group = "TEESimulator-RS Module Installation"
                    description =
                        "Pushes the ${variant.name} module to the device for $rootProvider."
                    dependsOn(zipTask)
                    commandLine(
                        "adb",
                        "push",
                        zipTask.get().archiveFile.get().asFile,
                        "/data/local/tmp",
                    )
                }

            val installTask =
                tasks.register<Exec>("install${rootProvider}${capitalized}") {
                    group = "TEESimulator-RS Module Installation"
                    description = "Installs the ${variant.name} module via $rootProvider."
                    dependsOn(pushTask)
                    commandLine(
                        "adb",
                        "shell",
                        "su",
                        "-c",
                        "$installCli /data/local/tmp/$zipFileName",
                    )
                }

            tasks.register<Exec>("install${rootProvider}AndReboot${capitalized}") {
                group = "TEESimulator-RS Module Installation"
                description = "Installs the ${variant.name} module via $rootProvider and reboots."
                dependsOn(installTask)
                commandLine("adb", "reboot")
            }
        }

        createInstallTasks("Magisk", "magisk --install-module")
        createInstallTasks("Ksu", "ksud module install")
        createInstallTasks("Apatch", "/data/adb/apd module install")
    }
}

val rkaArchivePath = providers.gradleProperty("rkaArchivePath")

val verifyRkaModuleArchive by
    tasks.registering {
        group = "TEESimulator-RS Module Packaging"
        description = "Verifies that the KSU archives contain only the role-neutral RKA runtime."
        if (!rkaArchivePath.isPresent) {
            dependsOn("zipRelease", "zipDebug")
        }
        inputs.property("rkaArchivePath", rkaArchivePath.orNull ?: "")

        doLast {
            val forbiddenEntryFragments =
                listOf(
                    "action",
                    "companion",
                    "customize",
                    "device-id",
                    "device_id",
                    "diag",
                    "keybox",
                    "persistent_keys",
                    "probe",
                    "profiles/",
                    "secrets/",
                    "trust/",
                    "update.json",
                )
            val commonEntries =
                setOf(
                    "daemon",
                    "rka-sidecar",
                    "rka-control.sh",
                    "rka-paths.sh",
                    "rka-profile.schema",
                    "rka-role.conf",
                    "rka-runtime.manifest",
                    "rka-supervisor.sh",
                    "sepolicy.rule",
                    "service.sh",
                    "uninstall.sh",
                    "webroot/index.html",
                    "webroot/app.js",
                    "webroot/style.css",
                    "licenses/NOTICE",
                    "licenses/LICENSE",
                    "META-INF/rka-artifacts.sha256",
                    "META-INF/rka-source.sha256",
                    "module.prop",
                ) +
                    rootProject.projectDir.resolve("module/webroot").walkTopDown().filter(File::isFile).map {
                        "webroot/${it.relativeTo(rootProject.projectDir.resolve("module/webroot")).invariantSeparatorsPath}"
                    }.toSet()
            val executableEntries =
                setOf(
                    "daemon",
                    "rka-control.sh",
                    "rka-paths.sh",
                    "rka-sidecar",
                    "rka-supervisor.sh",
                    "service.sh",
                    "uninstall.sh",
                )
            val resolvedArchives =
                if (rkaArchivePath.isPresent) {
                    listOf(rootProject.file(rkaArchivePath.get()))
                } else {
                    listOf(
                        rootProject.projectDir.resolve("out/TEESimulator-RS-$verName-$gitCommitCount-Release.zip"),
                        rootProject.projectDir.resolve("out/TEESimulator-RS-$verName-$gitCommitCount-Debug.zip"),
                    )
                }
            resolvedArchives.forEach { archive ->
                require(archive.isFile) { "Archive $archive does not exist." }
                CommonsZipFile(archive).use { zip ->
                    val entries = zip.entries.asSequence().filterNot { it.isDirectory }.toList()
                    val names = entries.map { it.name }.toSet()
                    fun reject(code: String): Nothing = error("RKA_VALIDATE:$code")
                    val forbiddenEntry = names.firstOrNull { entry -> forbiddenEntryFragments.any(entry.lowercase()::contains) }
                    if (forbiddenEntry != null) reject("FORBIDDEN_ENTRY")
                    val sourceWebUi = commonEntries.filter { it.startsWith("webroot/") }.toSet()
                    val archiveWebUi = names.filter { it.startsWith("webroot/") }.toSet()
                    if (!archiveWebUi.containsAll(sourceWebUi)) reject("WEBUI_MISSING")
                    if (!sourceWebUi.containsAll(archiveWebUi)) reject("WEBUI_EXTRA")
                    val sourceManifest = rootProject.projectDir.resolve("module/rka-runtime.manifest").readBytes()
                    val archiveManifest = zip.getInputStream(zip.getEntry("rka-runtime.manifest")).readBytes()
                    if (!archiveManifest.contentEquals(sourceManifest)) reject("MANIFEST_MISMATCH")
                    if (!names.containsAll(commonEntries)) reject("ENTRY_MISSING")
                    val variantEntry = if (archive.name.endsWith("-Release.zip")) "classes.dex" else "service.apk"
                    require(names.contains(variantEntry)) { "Archive $archive lacks $variantEntry." }
                    if (!names.all { entry ->
                        entry in commonEntries || entry == variantEntry || entry.startsWith("lib/")
                    }) reject("UNEXPECTED_ENTRY")
                    entries.forEach { entry ->
                        val expectedMode = if (entry.name in executableEntries) 0b111101101 else 0b110100100
                        if ((entry.unixMode and 0b111111111) != expectedMode) reject("MODE_MISMATCH")
                    }
                    val roleConfig = zip.getInputStream(zip.getEntry("rka-role.conf")).bufferedReader().readText()
                    if (roleConfig != "version=1\nrole=LOCAL\n") reject("ROLE_SPECIFIC")
                    entries.filter { entry ->
                        entry.name.endsWith(".sh") ||
                            entry.name.endsWith(".conf") ||
                            entry.name.endsWith(".manifest") ||
                            entry.name.endsWith(".schema") ||
                            entry.name.endsWith(".html") ||
                            entry.name.endsWith(".js") ||
                            entry.name.endsWith(".css")
                    }.forEach { entry ->
                        val text = zip.getInputStream(entry).bufferedReader().readText().lowercase()
                        if (text.contains("private key") || text.contains("reboot") || text.contains("adb ") || text.contains("start-service")) reject("FORBIDDEN_CONTENT")
                    }
                    val sidecar = zip.getEntry("rka-sidecar") ?: error("Archive $archive lacks rka-sidecar.")
                    val magic = zip.getInputStream(sidecar).readNBytes(4)
                    require(magic.contentEquals(byteArrayOf(0x7f, 0x45, 0x4c, 0x46))) {
                        "Archive $archive has a non-ELF sidecar."
                    }
                }
            }
        }
    }
