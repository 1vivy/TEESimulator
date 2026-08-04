package org.matrix.TEESimulator.rka.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.candidate.IdentityHash

class BrokerBridgeLifecycleTest {
    @Test
    fun cancellingOneCandidateProvisioningLeavesTheOtherActive() {
        // Given
        val candidateA = IdentityHash.of(ByteArray(32) { 1 })
        val candidateB = IdentityHash.of(ByteArray(32) { 2 })
        val requestA = RequestId(101)
        val requestB = RequestId(102)
        val cancellationA = BrokerCancellation.active()
        val cancellationB = BrokerCancellation.active()
        registerProvisioning(candidateA, requestA, cancellationA)
        registerProvisioning(candidateB, requestB, cancellationB)

        try {
            // When
            cancelProvisioning(candidateA)

            // Then
            assertTrue(provisioningIsActive(candidateB, requestB))
            assertFalse(cancellationB.isCancelled())
        } finally {
            resetProvisioningState()
        }
    }

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
            testBrokerBridgeClient(
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
        val dispatchEntered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val request =
            BridgeMessage.PublicKeyRequest(RequestId(92), PublicBytes.of(ByteArray(16), 64), 1)
        val transport =
            DuplexTransport(
                BridgeCodec.encode(request, BridgeDirection.SIDECAR_TO_BROKER),
                PeerCredentials(0, 0, 42),
            )
        val endpoint =
            testBrokerBridgeEndpoint(
                expected = { snapshot() },
                processIdentity = ProcessIdentitySource { observed() },
                socketMetadata = { SocketMetadata.secureRootOwned() },
                transport = transport,
                timeoutMillis = 100,
            )

        val started = System.nanoTime()
        val result =
            endpoint.acceptAndDispatch {
                dispatchEntered.countDown()
                release.await()
                BridgeMessage.PublicKeyResponse(
                    it.requestId,
                    PublicBytes.of(byteArrayOf(1), BridgeLimits.MAX_FRAME_BYTES),
                    testBatchId(),
                    Hash32.of(ByteArray(32)),
                    testKeyMetadata(Hash32.of(ByteArray(32))),
                )
            }
        val elapsedMillis =
            java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        release.countDown()

        assertTrue(dispatchEntered.await(1, java.util.concurrent.TimeUnit.SECONDS))
        assertEquals(BridgeError.DeadlineExceeded, result.failure())
        assertTrue("deadline took $elapsedMillis ms", elapsedMillis < 1_000)
        assertTrue(transport.closed)
        assertEquals(0, endpoint.correlationCountForTest())
    }

    @Test
    fun no_state_lock_is_held_across_peer_io_procfs_or_dispatch() {
        lateinit var endpoint: TestBrokerBridgeEndpoint
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
            testBrokerBridgeEndpoint(
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

private fun registerProvisioning(
    candidate: IdentityHash,
    requestId: RequestId,
    cancellation: BrokerCancellation,
) {
    val method =
        DonorProvisioningRuntime::class.java.declaredMethods.singleOrNull {
            it.name.startsWith("registerActiveProvisioning") && it.parameterCount == 3
        }
    if (method != null) {
        method.isAccessible = true
        val encodedRequestId =
            if (method.parameterTypes[1] == Long::class.javaPrimitiveType) requestId.value
            else requestId
        method.invoke(DonorProvisioningRuntime, candidate, encodedRequestId, cancellation)
        return
    }
    provisioningField("activeRequestId").set(DonorProvisioningRuntime, requestId)
    provisioningField("activeCancellation").set(DonorProvisioningRuntime, cancellation)
}

private fun cancelProvisioning(candidate: IdentityHash) {
    val method =
        DonorProvisioningRuntime::class.java.declaredMethods.singleOrNull {
            it.name.startsWith("cancelActiveProvisioning") && it.parameterCount == 1
        }
    if (method != null) {
        method.isAccessible = true
        method.invoke(DonorProvisioningRuntime, candidate)
        return
    }
    (provisioningField("activeCancellation").get(DonorProvisioningRuntime) as? BrokerCancellation)
        ?.cancel()
    provisioningField("activeCancellation").set(DonorProvisioningRuntime, null)
    provisioningField("activeRequestId").set(DonorProvisioningRuntime, null)
}

private fun provisioningIsActive(candidate: IdentityHash, requestId: RequestId): Boolean {
    val method =
        DonorProvisioningRuntime::class.java.declaredMethods.singleOrNull {
            it.name.startsWith("activeProvisioningMatches") && it.parameterCount == 2
        }
    if (method != null) {
        method.isAccessible = true
        val encodedRequestId =
            if (method.parameterTypes[1] == Long::class.javaPrimitiveType) requestId.value
            else requestId
        return method.invoke(DonorProvisioningRuntime, candidate, encodedRequestId) as Boolean
    }
    return provisioningField("activeRequestId").get(DonorProvisioningRuntime) == requestId
}

@Suppress("UNCHECKED_CAST")
private fun resetProvisioningState() {
    listOf("activeRequestIds", "activeCancellations", "quarantineControllers").forEach { name ->
        runCatching {
            (provisioningField(name).get(DonorProvisioningRuntime) as MutableMap<Any, Any>).clear()
        }
    }
    listOf("activeRequestId", "activeCancellation").forEach { name ->
        runCatching { provisioningField(name).set(DonorProvisioningRuntime, null) }
    }
}

private fun provisioningField(name: String) =
    DonorProvisioningRuntime::class.java.getDeclaredField(name).apply { isAccessible = true }
