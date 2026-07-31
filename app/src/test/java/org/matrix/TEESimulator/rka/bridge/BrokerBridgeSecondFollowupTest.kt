package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerBridgeSecondFollowupTest {
    @Test
    fun production_identity_cannot_be_supplied_by_public_callback() {
        assertEquals(0, BrokerBridgeEndpoint::class.java.constructors.size)
        assertEquals(0, BrokerBridgeClient::class.java.constructors.size)
    }

    @Test
    fun blocking_accept_and_connect_are_not_public() {
        assertFalse(DonorBridgeServer::class.java.methods.any { it.name == "accept" })
        assertFalse(CandidateBridgeConnector::class.java.methods.any { it.name == "connect" })
    }

    @Test
    fun external_consumer_cannot_compile_a_blocking_or_forgeable_bypass() {
        val root = Files.createTempDirectory("bridge-consumer")
        try {
            val source = root.resolve("ExternalBypass.java")
            Files.write(
                source,
                """
                import java.nio.file.Path;
                import org.matrix.TEESimulator.rka.bridge.*;
                final class ExternalBypass {
                  void bypass(DonorBridgeServer server) {
                    new BrokerBridgeEndpoint();
                    server.accept();
                    CandidateBridgeConnector.INSTANCE.connect(Path.of("/tmp/socket"));
                  }
                }
                """
                    .trimIndent()
                    .toByteArray(),
            )
            val process =
                ProcessBuilder(
                        Path.of(System.getProperty("java.home"), "bin", "javac").toString(),
                        "-proc:none",
                        "-classpath",
                        System.getProperty("java.class.path"),
                        source.toString(),
                    )
                    .redirectErrorStream(true)
                    .start()
            process.inputStream.readBytes()
            val exit = process.waitFor()

            assertTrue("external bypass unexpectedly compiled", exit != 0)
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun sepolicy_uses_only_dedicated_rka_socket_types() {
        val policy = String(Files.readAllBytes(repositoryRoot().resolve("module/sepolicy.rule")))

        assertFalse(policy.contains("adb_data_file:sock_file"))
        assertFalse(
            policy.lineSequence().any {
                it.startsWith("allow ksu adb_data_file:dir") ||
                    it.startsWith("allow magisk adb_data_file:dir")
            }
        )
        assertTrue(policy.contains("type teesimulator_rka_socket_dir file_type\n"))
        assertTrue(policy.contains("type teesimulator_rka_socket file_type\n"))
        assertTrue(
            policy.contains(
                "type_transition ksu adb_data_file dir teesimulator_rka_socket_dir sockets\n"
            )
        )
        assertTrue(
            policy.contains(
                "type_transition magisk adb_data_file dir teesimulator_rka_socket_dir sockets\n"
            )
        )
        assertTrue(
            policy.contains(
                "type_transition ksu teesimulator_rka_socket_dir sock_file " +
                    "teesimulator_rka_socket broker.sock\n"
            )
        )
        assertTrue(
            policy.contains(
                "type_transition magisk teesimulator_rka_socket_dir sock_file " +
                    "teesimulator_rka_socket broker.sock\n"
            )
        )
    }

    @Test
    fun success_transfers_live_response_ownership_to_caller() {
        val request =
            BridgeMessage.PublicKeyRequest(RequestId(301), PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            MemoryTransport(BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER))
        val endpoint =
            testBrokerBridgeEndpoint(
                expected = { snapshot() },
                processIdentity = ProcessIdentitySource { observed() },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
            )

        val result =
            endpoint.acceptAndDispatch {
                BridgeMessage.PublicKeyResponse(
                    it.requestId,
                    PublicBytes.of(byteArrayOf(7, 8, 9), BridgeLimits.MAX_FRAME_BYTES),
                    testKeyMetadata(Hash32.of(ByteArray(32))),
                )
            }
        val response = (result as BridgeResult.Success).value as BridgeMessage.PublicKeyResponse

        assertTrue(response.publicCsr.copyBytes().contentEquals(byteArrayOf(7, 8, 9)))
        response.close()
        assertEquals(
            "public bytes destroyed",
            org.junit.Assert.assertThrows(IllegalStateException::class.java) {
                    response.publicCsr.copyBytes()
                }
                .message,
        )
    }

    private fun repositoryRoot(): Path {
        var path = Path.of(System.getProperty("user.dir")).toAbsolutePath()
        while (!Files.exists(path.resolve("settings.gradle.kts"))) {
            path = path.parent ?: error("repository root not found")
        }
        return path
    }

    private fun snapshot() =
        SupervisorSnapshot(
            generation = 9,
            uid = 0,
            gid = 0,
            pid = 42,
            startTimeTicks = 777,
            cmdline = listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
            executablePath = "/data/adb/teesimulator-rka/bin/rka-sidecar",
            executableInode = 1234,
        )

    private fun observed() =
        ObservedProcessIdentity(
            startTimeTicks = 777,
            cmdline = listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
            executablePath = "/data/adb/teesimulator-rka/bin/rka-sidecar",
            executableInode = 1234,
        )

    private class MemoryTransport(bytes: ByteArray) : BridgeTransport {
        private val source = ByteArrayInputStream(bytes)
        private val sink = ByteArrayOutputStream()

        override fun peerCredentials(): PeerCredentials = PeerCredentials(0, 0, 42)

        override fun input(): InputStream = source

        override fun output() = sink

        override fun close() = Unit
    }
}
