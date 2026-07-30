package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrokerBridgeLifecycleTest {
    @Test
    fun candidate_client_performs_encoded_correlated_exchange() {
        val snapshot = snapshot()
        val request = BridgeMessage.Cancel(RequestId(91))
        val response =
            BridgeMessage.Error(
                RequestId(91),
                BridgeErrorCode.CANCELLED,
                Hash32.of(ByteArray(32) { 4 }),
            )
        val transport =
            DuplexTransport(
                BridgeCodec.encode(response, BridgeDirection.SIDECAR_TO_BROKER),
                PeerCredentials(0, 0, 42),
            )
        val client =
            BrokerBridgeClient(
                expected = { snapshot },
                processIdentity = ProcessIdentitySource { observed() },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
            )

        val result = client.exchange(request)

        assertTrue(result is BridgeResult.Success)
        val sent =
            BridgeCodec.decode(
                ByteArrayInputStream(transport.written.toByteArray()),
                BridgeDirection.BROKER_TO_SIDECAR,
            )
        assertTrue(sent is BridgeResult.Success)
        assertEquals(RequestId(91), (sent as BridgeResult.Success).value.requestId)
    }

    @Test
    fun aggregate_deadline_includes_authentication_io_and_dispatch() {
        val now = AtomicLong()
        val snapshot = snapshot()
        val request = BridgeMessage.Cancel(RequestId(92))
        val transport =
            object :
                DuplexTransport(
                    BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER),
                    PeerCredentials(0, 0, 42),
                ) {
                override fun input(): ByteArrayInputStream {
                    now.addAndGet(2_000_000_000)
                    return super.input()
                }
            }
        val endpoint =
            BrokerBridgeEndpoint(
                expected = { snapshot },
                processIdentity =
                    ProcessIdentitySource {
                        now.addAndGet(2_000_000_000)
                        observed()
                    },
                socketMetadata = {
                    now.addAndGet(1_500_000_000)
                    SocketMetadata.secureRootOwned()
                },
                clock = now::get,
                transport = transport,
            )

        val result = endpoint.acceptAndDispatch { request }

        assertEquals(BridgeError.DeadlineExceeded, result.failure())
        assertTrue(transport.closed)
    }

    @Test
    fun no_state_lock_is_held_across_peer_io_procfs_or_dispatch() {
        lateinit var endpoint: BrokerBridgeEndpoint
        val request = BridgeMessage.Cancel(RequestId(93))
        val transport =
            object :
                DuplexTransport(
                    BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER),
                    PeerCredentials(0, 0, 42),
                ) {
                override fun peerCredentials(): PeerCredentials {
                    assertFalse(endpoint.stateLockHeldByCurrentThread())
                    return super.peerCredentials()
                }

                override fun input(): ByteArrayInputStream {
                    assertFalse(endpoint.stateLockHeldByCurrentThread())
                    return super.input()
                }

                override fun output(): ByteArrayOutputStream {
                    assertFalse(endpoint.stateLockHeldByCurrentThread())
                    return super.output()
                }
            }
        endpoint =
            BrokerBridgeEndpoint(
                expected = { snapshot() },
                processIdentity =
                    ProcessIdentitySource {
                        assertFalse(endpoint.stateLockHeldByCurrentThread())
                        observed()
                    },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
            )

        val result =
            endpoint.acceptAndDispatch {
                assertFalse(endpoint.stateLockHeldByCurrentThread())
                it
            }

        assertTrue(result is BridgeResult.Success)
    }

    @Test
    fun peer_identity_checks_every_credential_and_process_field() {
        val expected = snapshot()
        val correctCredentials = PeerCredentials(0, 0, 42)
        val correctObserved = observed()
        assertTrue(identityMatches(correctCredentials, expected, correctObserved))
        assertFalse(identityMatches(correctCredentials.copy(uid = 1), expected, correctObserved))
        assertFalse(identityMatches(correctCredentials.copy(gid = 1), expected, correctObserved))
        assertFalse(identityMatches(correctCredentials.copy(pid = 43), expected, correctObserved))
        assertFalse(
            identityMatches(
                correctCredentials,
                expected,
                correctObserved.copy(startTimeTicks = 778),
            )
        )
        assertFalse(
            identityMatches(
                correctCredentials,
                expected,
                correctObserved.copy(cmdline = listOf("/wrong")),
            )
        )
        assertFalse(
            identityMatches(
                correctCredentials,
                expected,
                correctObserved.copy(executablePath = "/wrong"),
            )
        )
        assertFalse(
            identityMatches(
                correctCredentials,
                expected,
                correctObserved.copy(executableInode = 1235),
            )
        )
    }

    private fun snapshot() =
        SupervisorSnapshot(
            3,
            0,
            0,
            42,
            777,
            listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
            "/data/adb/teesimulator-rka/bin/rka-sidecar",
            1234,
        )

    private fun observed() =
        ObservedProcessIdentity(
            777,
            listOf("/data/adb/teesimulator-rka/bin/rka-sidecar", "--role", "donor"),
            "/data/adb/teesimulator-rka/bin/rka-sidecar",
            1234,
        )

    private fun BridgeResult<*>.failure(): BridgeError = (this as BridgeResult.Failure).error

    private open class DuplexTransport(bytes: ByteArray, private val credentials: PeerCredentials) :
        BridgeTransport {
        private val source = ByteArrayInputStream(bytes)
        val written = ByteArrayOutputStream()
        var closed = false

        override fun peerCredentials(): PeerCredentials = credentials

        override fun input(): ByteArrayInputStream = source

        override fun output(): ByteArrayOutputStream = written

        override fun close() {
            closed = true
        }
    }
}
