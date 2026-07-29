package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec

class AndroidWireDonorBackendOperationTest {
    private val operationSpec = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)

    @Test
    fun unsupportedOperationSpecsFailBeforeRepositoryOrKeystoreAccess() {
        val rig = PhysicalBackendTestRig()
        val backend = rig.backend()
        val generated = backend.generate(rig.generateCommand())
        val saveAttempts = rig.stateStore.saveAttempts
        rig.keyStoreBackend.calls.clear()

        listOf(unsupportedSpec("purpose"), unsupportedSpec("digest")).forEach { unsupported ->
            assertWireFailure(WireErrorCode.INVALID_ARGUMENT) {
                backend.begin(generated.handle, unsupported, rig.caller)
            }
        }

        assertEquals(saveAttempts, rig.stateStore.saveAttempts)
        assertTrue(rig.keyStoreBackend.calls.isEmpty())
        assertTrue(rig.keyStoreBackend.operations.isEmpty())

        val operation = backend.begin(generated.handle, operationSpec, rig.caller)
        assertEquals(listOf("metadata", "begin"), rig.keyStoreBackend.calls)
        assertEquals(1, rig.keyStoreBackend.operations.size)
        backend.abort(operation, rig.caller)
    }

    @Test
    fun operationHandlesAreBoundToSessionPairCallerAndLocalRegistry() {
        val rig = PhysicalBackendTestRig()
        val owner = rig.backend(rig.session(1))
        val generated = owner.generate(rig.generateCommand())
        val operation = owner.begin(generated.handle, operationSpec, rig.caller)
        rig.keyStoreBackend.calls.clear()
        rig.keyStoreBackend.operations.single().calls.clear()

        val attempts =
            listOf(rig.backend(rig.session(2)), rig.backend(rig.session(1), rig.otherPair))
        attempts.forEach { backend ->
            assertWireFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
                backend.update(operation, byteArrayOf(1), rig.caller)
            }
        }
        assertWireFailure(WireErrorCode.WRONG_CALLER) {
            owner.update(operation, byteArrayOf(1), rig.otherCaller)
        }

        assertTrue(rig.keyStoreBackend.calls.isEmpty())
        assertTrue(rig.keyStoreBackend.operations.single().calls.isEmpty())
        owner.abort(operation, rig.caller)
    }

    @Test
    fun updateAndFinishFailuresRemoveSessionRecords() {
        val rig = PhysicalBackendTestRig()
        val backend = rig.backend()
        val generated = backend.generate(rig.generateCommand())
        val updateOperation = backend.begin(generated.handle, operationSpec, rig.caller)
        rig.keyStoreBackend.operations[0].updateFailure =
            AndroidKeystoreDonorException.BackendFailure(IllegalStateException())

        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) {
            backend.update(updateOperation, byteArrayOf(1), rig.caller)
        }
        assertWireFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
            backend.update(updateOperation, byteArrayOf(1), rig.caller)
        }

        val finishOperation = backend.begin(generated.handle, operationSpec, rig.caller)
        rig.keyStoreBackend.operations[1].finishFailure =
            AndroidKeystoreDonorException.BackendFailure(IllegalStateException())
        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) {
            backend.finish(finishOperation, byteArrayOf(2), rig.caller)
        }
        assertWireFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
            backend.abort(finishOperation, rig.caller)
        }
        assertEquals(1, rig.keyStoreBackend.operations[0].abortCount)
        assertEquals(1, rig.keyStoreBackend.operations[1].abortCount)
    }

    @Test
    fun closeAbortsOnlyOwnedOperationsIsIdempotentAndMakesMethodsUnavailable() {
        val rig = PhysicalBackendTestRig()
        val first = rig.backend(rig.session(3))
        val second = rig.backend(rig.session(4))
        val generated = first.generate(rig.generateCommand())
        val firstOperation = first.begin(generated.handle, operationSpec, rig.caller)
        val secondOperation = second.begin(generated.handle, operationSpec, rig.caller)

        first.close()
        first.close()

        assertEquals(1, rig.keyStoreBackend.operations[0].abortCount)
        assertEquals(0, rig.keyStoreBackend.operations[1].abortCount)
        assertContentEquals(
            ByteArray(0),
            second.update(secondOperation, byteArrayOf(1), rig.caller),
        )
        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) {
            first.abort(firstOperation, rig.caller)
        }
        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) {
            first.metadata(generated.handle, rig.caller)
        }
        second.abort(secondOperation, rig.caller)
    }

    @Test
    fun sessionInputsOperationInputsAndResultsAreDefensive() {
        val rig = PhysicalBackendTestRig()
        val sessionId = rig.session(5)
        val backend = rig.backend(sessionId)
        sessionId.fill(0)
        val generated = backend.generate(rig.generateCommand())
        val operation = backend.begin(generated.handle, operationSpec, rig.caller)
        val input = byteArrayOf(7, 8)
        backend.update(operation, input, rig.caller)
        input.fill(0)
        assertContentEquals(
            byteArrayOf(7, 8),
            rig.keyStoreBackend.operations.single().inputs.single(),
        )

        val output = backend.finish(operation, byteArrayOf(9), rig.caller)
        output.fill(0)
        assertContentEquals(
            FakeSignOperation.SIGNATURE,
            rig.keyStoreBackend.operations.single().finishResult,
        )
    }

    @Test
    fun invalidSessionAndUnknownAuthenticatedOperationUseNarrowCodes() {
        val rig = PhysicalBackendTestRig()
        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) { rig.backend(ByteArray(31)) }
        val backend = rig.backend()
        val unknown =
            rig.authenticator.createOperationHandle(
                rig.session(1),
                HandleScope(rig.pair, rig.caller),
                testUuid(999),
                testUuid(998),
            )
        assertWireFailure(WireErrorCode.INVALID_OPERATION_HANDLE) {
            backend.update(
                WireOperationHandle(unknown.id, unknown.keyId, unknown.binding),
                byteArrayOf(),
                rig.caller,
            )
        }
    }

    private fun unsupportedSpec(fieldName: String): WireOperationSpec =
        WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256).also { spec ->
            WireOperationSpec::class.java.getDeclaredField(fieldName).apply {
                isAccessible = true
                set(spec, null)
            }
        }
}
