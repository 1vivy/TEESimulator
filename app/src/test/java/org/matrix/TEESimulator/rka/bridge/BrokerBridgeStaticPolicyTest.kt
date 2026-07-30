package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerBridgeStaticPolicyTest {
    @Test
    fun bridge_sources_exclude_forbidden_platform_and_secret_material() {
        val root = repositoryRoot()
        val sourceRoot = root.resolve("app/src/main/java/org/matrix/TEESimulator/rka/bridge")
        val source =
            Files.walk(sourceRoot).use { paths ->
                paths
                    .filter { Files.isRegularFile(it) }
                    .map { String(Files.readAllBytes(it)) }
                    .toList()
                    .joinToString("\n")
            }
        for (forbidden in
            listOf(
                "android.os.IBinder",
                "android.os.Parcel",
                "keyBlob",
                "privateKey",
                "transportSecret",
                "GenericMap",
                "JSONObject",
                "Gson",
            )) {
            assertFalse("forbidden bridge material/API: $forbidden", source.contains(forbidden))
        }
    }

    @Test
    fun sepolicy_is_exact_and_not_broad() {
        val policy = String(Files.readAllBytes(repositoryRoot().resolve("module/sepolicy.rule")))
        assertTrue(policy.contains("allow ksu self:unix_stream_socket"))
        assertTrue(policy.contains("allow magisk self:unix_stream_socket"))
        assertFalse(
            policy.lineSequence().any { it.contains("unix_stream_socket") && it.contains("*") }
        )
        assertFalse(policy.lineSequence().any { it.trimStart().startsWith("permissive ") })
        assertFalse(policy.lineSequence().any { it.trimStart().startsWith("typeattribute ") })
    }

    @Test
    fun production_app_has_no_companion_dependency() {
        val build = String(Files.readAllBytes(repositoryRoot().resolve("app/build.gradle.kts")))
        assertFalse(build.contains("project(\":rka-fixture\")"))
        assertFalse(build.contains("CandidateCompanionService"))
    }

    private fun repositoryRoot(): Path {
        var path = Path.of(System.getProperty("user.dir")).toAbsolutePath()
        while (!Files.exists(path.resolve("settings.gradle.kts"))) {
            path = path.parent ?: error("repository root not found")
        }
        return path
    }
}
