package org.matrix.teesimulator.physicalharness

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.matrix.teesimulator.twophone.BeginRequestPayload
import org.matrix.teesimulator.twophone.BeginResultPayload
import org.matrix.teesimulator.twophone.DeleteRequestPayload
import org.matrix.teesimulator.twophone.FinishRequestPayload
import org.matrix.teesimulator.twophone.FinishResultPayload
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.GenerateResultPayload
import org.matrix.teesimulator.twophone.GetMetadataRequestPayload
import org.matrix.teesimulator.twophone.GetMetadataResultPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.UpdateRequestPayload
import org.matrix.teesimulator.twophone.UpdateResultPayload
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireDonorDispatcher
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireOperationSpec
import org.matrix.teesimulator.twophone.WireOutcome

class AndroidWireDonorBackendDispatcherTest {
    @Test
    fun dispatcherRunsFullDurableSigningLifecycle() {
        val rig = PhysicalBackendTestRig()
        val clientNonce = testBytes(32, 31)
        val serverNonce = testBytes(32, 32)
        val sessionId = derivedSessionId(rig.pair, clientNonce, serverNonce)
        val dispatcher =
            WireDonorDispatcher(
                rig.pair,
                clientNonce,
                serverNonce,
                { Instant.parse("2026-07-25T12:00:00Z") },
                rig.backend(sessionId),
            )
        var sequence = 0uL
        val generate =
            GenerateRequestPayload(testUuid(1), testBytes(32, 2), testBytes(32, 3), testKeySpec)
        val generated =
            success<GenerateResultPayload>(
                dispatcher.dispatch(rig.request(generate, clientNonce, serverNonce, sequence++))
            )
        val metadata =
            success<GetMetadataResultPayload>(
                    dispatcher.dispatch(
                        rig.request(
                            GetMetadataRequestPayload(generated.handle),
                            clientNonce,
                            serverNonce,
                            sequence++,
                        )
                    )
                )
                .metadata
        val begun =
            success<BeginResultPayload>(
                dispatcher.dispatch(
                    rig.request(
                        BeginRequestPayload(
                            testUuid(4),
                            0uL,
                            generated.handle,
                            WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256),
                        ),
                        clientNonce,
                        serverNonce,
                        sequence++,
                    )
                )
            )
        val updated =
            success<UpdateResultPayload>(
                dispatcher.dispatch(
                    rig.request(
                        UpdateRequestPayload(begun.operation, 1uL, byteArrayOf(5, 6)),
                        clientNonce,
                        serverNonce,
                        sequence++,
                    )
                )
            )
        val finished =
            success<FinishResultPayload>(
                dispatcher.dispatch(
                    rig.request(
                        FinishRequestPayload(begun.operation, 2uL, byteArrayOf(7, 8)),
                        clientNonce,
                        serverNonce,
                        sequence++,
                    )
                )
            )
        success<org.matrix.teesimulator.twophone.DeleteResultPayload>(
            dispatcher.dispatch(
                rig.request(
                    DeleteRequestPayload(testUuid(9), generated.handle),
                    clientNonce,
                    serverNonce,
                    sequence,
                )
            )
        )

        assertEquals(KeyState.ACTIVE, metadata.state)
        assertContentEquals(ByteArray(0), updated.output)
        assertContentEquals(FakeSignOperation.SIGNATURE, finished.output)
        assertEquals(1, rig.keyStoreBackend.deletedAliases.size)
    }

    @Test
    fun processBackendsShareLifecycleButKeepSessionOperationsSeparate() {
        val rig = PhysicalBackendTestRig()
        val first = rig.backend(rig.session(10))
        val second = rig.backend(rig.session(11))
        val generated = first.generate(rig.generateCommand())

        assertEquals(KeyState.ACTIVE, second.metadata(generated.handle, rig.caller).state)
        val operation =
            first.begin(
                generated.handle,
                WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256),
                rig.caller,
            )
        assertWireFailure(org.matrix.teesimulator.twophone.WireErrorCode.INVALID_OPERATION_HANDLE) {
            second.update(operation, byteArrayOf(1), rig.caller)
        }
        second.close()
        assertContentEquals(ByteArray(0), first.update(operation, byteArrayOf(2), rig.caller))
        first.abort(operation, rig.caller)
    }

    private inline fun <reified T> success(
        response: org.matrix.teesimulator.twophone.WireResponseEnvelope
    ): T = assertIs<T>(assertIs<WireOutcome.Success>(response.outcome).payload)
}

internal fun assertWireFailure(
    code: org.matrix.teesimulator.twophone.WireErrorCode,
    block: () -> Unit,
) {
    val failure =
        kotlin.test.assertFailsWith<org.matrix.teesimulator.twophone.WireBackendFailure> { block() }
    assertEquals(code, failure.code)
}
