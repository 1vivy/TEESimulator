package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerBridgeFourthFollowupTest {
    @Test
    fun production_uses_the_arm64_directory_open_flag() {
        for (sourceName in listOf("SecureSocketPath.kt", "TrustedSidecarIdentity.kt")) {
            val source = productionSource(sourceName)

            assertTrue(source.contains("O_DIRECTORY = 0x4000"))
            assertFalse(source.contains("O_DIRECTORY = 0x10000"))
        }
    }

    @Test
    fun public_factory_binds_expected_role_before_any_socket_operation() {
        val factory = productionSource("BrokerBridgeFactory.kt")
        val donorCapture =
            factory.indexOf("captureProductionPeerAuthorization(BrokerSidecarRole.DONOR)")
        val candidateCapture =
            factory.indexOf("captureProductionPeerAuthorization(BrokerSidecarRole.CANDIDATE)")

        assertTrue(donorCapture >= 0)
        assertTrue(candidateCapture >= 0)
        assertTrue(donorCapture < factory.indexOf("DonorBridgeServer.bind()"))
        assertTrue(
            candidateCapture < factory.indexOf("CandidateBridgeConnector.boundedTransport()")
        )
    }

    @Test
    fun production_uses_type_transitions_and_never_relabels_socket_objects() {
        val socketPath = productionSource("SecureSocketPath.kt")
        val policy = String(Files.readAllBytes(repositoryRoot().resolve("module/sepolicy.rule")))

        assertFalse(socketPath.contains("setFileContext"))
        assertFalse(socketPath.contains("restorecon"))
        assertFalse(policy.contains("relabelfrom"))
        assertFalse(policy.contains("relabelto"))
        for (domain in listOf("ksu")) {
            assertTrue(
                policy.contains(
                    "type_transition $domain adb_data_file dir " +
                        "teesimulator_rka_socket_dir sockets"
                )
            )
            assertTrue(
                policy.contains(
                    "type_transition $domain teesimulator_rka_socket_dir sock_file " +
                        "teesimulator_rka_socket broker.sock"
                )
            )
        }
        assertFalse(policy.contains("magisk"))
        assertTrue(socketPath.contains("fileContext(directoryAnchor) == DIRECTORY_CONTEXT"))
        assertTrue(socketPath.contains("fileContext(nodeAnchor)"))
        assertTrue(socketPath.contains("SOCKET_CONTEXT"))
    }

    @Test
    fun custom_socket_policy_has_only_the_exact_runtime_access_rules() {
        val policy =
            String(Files.readAllBytes(repositoryRoot().resolve("module/sepolicy.rule")))
                .lineSequence()
                .map(String::trim)
                .filter(String::isNotEmpty)
                .toList()
        val expected =
            setOf(
                "allow ksu ksu unix_stream_socket { create bind connect listen accept read write getattr getopt setopt shutdown }",
                "allow ksu teesimulator_rka_socket_dir dir { search open read getattr write add_name remove_name setattr }",
                "allow ksu teesimulator_rka_socket sock_file { create open read write getattr setattr unlink }",
            )
        val actual =
            policy
                .filter {
                    it.startsWith("allow ") &&
                        (it.contains(" unix_stream_socket ") ||
                            it.contains(" teesimulator_rka_socket"))
                }
                .toSet()

        assertTrue(actual == expected)
        assertFalse(actual.any { it.contains(" *") })
        assertFalse(policy.any { it.contains("relabel") })
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
