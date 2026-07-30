package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerBridgeThirdFollowupTest {
    @Test
    fun production_contains_no_forgeable_identity_test_or_configurable_source_api() {
        val production = productionBridgeSources()

        listOf(
                "TestTrustedSidecarIdentitySource",
                "testTrustedSidecarIdentitySource",
                "BrokerBridgeEndpoints",
                "BrokerBridgeClients",
                "fun forTest(",
                "recordPath:",
                "requiredUid:",
                "requiredGid:",
            )
            .forEach { forbidden ->
                assertFalse(
                    "forbidden production trust seam: $forbidden",
                    production.contains(forbidden),
                )
            }
    }

    @Test
    fun public_production_factory_has_only_fixed_role_operations() {
        assertEquals(0, BrokerBridgeFactory::class.java.constructors.size)
        assertEquals(
            setOf("acceptDonor", "exchangeCandidate"),
            BrokerBridgeFactory::class
                .java
                .declaredMethods
                .filter { java.lang.reflect.Modifier.isPublic(it.modifiers) }
                .map { it.name }
                .toSet(),
        )
    }

    @Test
    fun supervisor_record_is_read_only_through_a_held_nofollow_descriptor() {
        val source = productionSource("TrustedSidecarIdentity.kt")

        assertFalse(source.contains("Files.readAllBytes"))
        assertTrue(source.contains("OsConstants.O_NOFOLLOW"))
        assertTrue(source.contains("OsConstants.O_CLOEXEC"))
        assertTrue(source.contains("Os.read(") || source.contains("Os.pread("))
        assertTrue(source.contains("Os.fstat("))
    }

    @Test
    fun socket_metadata_label_and_removal_are_anchored_to_held_node_and_directory_handles() {
        val source =
            productionSource("SecureSocketPath.kt") + productionSource("BrokerBridgeSockets.kt")

        assertFalse(source.contains("fileContext(anchoredSocketPath)"))
        assertFalse(source.contains("setAndVerifyContext(anchoredSocketPath"))
        assertFalse(source.contains("Os.remove(anchoredSocketPath"))
        assertTrue(source.contains("BridgeSocketNodeHandle"))
        assertTrue(source.contains("SecureDirectoryStream"))
        assertTrue(source.contains("openDirectoryComponent"))
    }

    private fun productionBridgeSources(): String {
        val directory =
            repositoryRoot()
                .resolve("app/src/main/java/org/matrix/TEESimulator/rka/bridge")
                .toFile()
        return directory
            .walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .joinToString("\n") { it.readText() }
    }

    private fun productionSource(name: String): String =
        String(
            Files.readAllBytes(
                repositoryRoot()
                    .resolve("app/src/main/java/org/matrix/TEESimulator/rka/bridge/$name")
            )
        )

    private fun repositoryRoot(): Path {
        var path = Path.of(System.getProperty("user.dir")).toAbsolutePath()
        while (!Files.exists(path.resolve("settings.gradle.kts"))) {
            path = path.parent ?: error("repository root not found")
        }
        return path
    }
}
