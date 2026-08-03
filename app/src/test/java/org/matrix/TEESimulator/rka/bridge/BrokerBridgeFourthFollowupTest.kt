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
    fun donor_listener_stays_bound_while_idle_and_only_connected_io_is_deadline_bounded() {
        val factory = productionSource("BrokerBridgeFactory.kt")
        val donorStart = factory.indexOf("fun acceptDonor(")
        val candidateStart = factory.indexOf("fun exchangeCandidate(")
        val donor = factory.substring(donorStart, candidateStart)

        assertTrue(donor.contains("value.nextTransport()"))
        assertTrue(donor.contains("createProductionBrokerEndpoint("))
        assertFalse(donor.contains("BoundedBridgeExecution().run("))
        assertFalse(donor.contains("InlineBridgeExecution"))
        assertFalse(donor.contains("value.close()"))
    }

    @Test
    fun production_relabels_only_the_anchored_bound_socket() {
        val socketPath = productionSource("SecureSocketPath.kt")
        val policy = String(Files.readAllBytes(repositoryRoot().resolve("module/sepolicy.rule")))

        assertTrue(socketPath.contains("setFileContext(nodeAnchor, SOCKET_CONTEXT)"))
        assertFalse(socketPath.contains("restorecon"))
        assertTrue(policy.contains("allow ksu unlabeled sock_file relabelfrom\n"))
        assertTrue(policy.contains("allow ksu adb_data_file sock_file relabelfrom\n"))
        assertTrue(policy.contains("allow ksu teesimulator_rka_socket sock_file relabelto\n"))
        assertTrue(policy.contains("allow ksu adb_data_file dir relabelfrom\n"))
        assertTrue(policy.contains("allow ksu teesimulator_rka_socket_dir dir relabelto\n"))
        for (domain in listOf("ksu")) {
            assertTrue(
                policy.contains(
                    "type_transition $domain adb_data_file dir " +
                        "teesimulator_rka_socket_dir sockets"
                )
            )
            assertFalse(
                policy.contains("type_transition $domain teesimulator_rka_socket_dir sock_file")
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
                "allow ksu unlabeled sock_file relabelfrom",
                "allow ksu adb_data_file sock_file relabelfrom",
                "allow ksu teesimulator_rka_socket_dir sock_file relabelfrom",
                "allow ksu teesimulator_rka_socket sock_file relabelto",
                "allow ksu adb_data_file dir relabelfrom",
                "allow ksu teesimulator_rka_socket_dir dir relabelto",
            )
        val actual =
            policy
                .filter {
                    it.startsWith("allow ") &&
                        (it.contains(" unix_stream_socket ") ||
                            it.contains(" teesimulator_rka_socket") ||
                            it.contains(" relabel"))
                }
                .toSet()

        assertTrue(actual == expected)
        assertFalse(actual.any { it.contains(" *") })
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
