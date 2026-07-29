package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireOperationSpec

class AndroidWireDonorBackendLifecycleTest {
    private val operationSpec = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)

    @Test
    fun wrongCallerIsRejectedBeforeRepositoryAndKeystoreAccess() {
        val rig = PhysicalBackendTestRig()
        val backend = rig.backend()
        val forged = WireKeyHandle(testUuid(999), testBytes(32, 8))
        val saveAttempts = rig.stateStore.saveAttempts
        rig.keyStoreBackend.calls.clear()

        assertWireFailure(WireErrorCode.WRONG_CALLER) {
            backend.generate(rig.generateCommand(caller = rig.otherCaller))
        }
        assertWireFailure(WireErrorCode.WRONG_CALLER) { backend.metadata(forged, rig.otherCaller) }
        assertWireFailure(WireErrorCode.WRONG_CALLER) {
            backend.delete(rig.deleteCommand(forged, caller = rig.otherCaller))
        }
        assertWireFailure(WireErrorCode.WRONG_CALLER) {
            backend.begin(forged, operationSpec, rig.otherCaller)
        }

        assertEquals(saveAttempts, rig.stateStore.saveAttempts)
        assertTrue(rig.keyStoreBackend.calls.isEmpty())
    }

    @Test
    fun repositoryReplayHandleStateAndUnavailableFailuresMapThroughBackend() {
        val rig = PhysicalBackendTestRig()
        val backend = rig.backend()
        val generationId = testUuid(300)
        val generated = backend.generate(rig.generateCommand(generationId = generationId))

        assertWireFailure(WireErrorCode.REPLAY_CONFLICT) {
            backend.generate(
                rig.generateCommand(generationId = generationId, challenge = testBytes(32, 99))
            )
        }
        assertWireFailure(WireErrorCode.INVALID_HANDLE) {
            backend.metadata(
                WireKeyHandle(generated.handle.id, generated.handle.binding.mutated(0)),
                rig.caller,
            )
        }
        backend.delete(rig.deleteCommand(generated.handle))
        assertWireFailure(WireErrorCode.INVALID_STATE) {
            backend.begin(generated.handle, operationSpec, rig.caller)
        }

        val nextAttempt = rig.stateStore.saveAttempts + 1
        rig.stateStore.failBeforeSaveAttempts += nextAttempt
        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) {
            backend.generate(rig.generateCommand(generationId = testUuid(301)))
        }
    }

    @Test
    fun missingKeystoreKeyAtBeginMapsUnavailable() {
        val rig = PhysicalBackendTestRig()
        val backend = rig.backend()
        val generated = backend.generate(rig.generateCommand())
        val alias = DonorKeyAliasPolicy.aliasFor(generated.handle.id)
        rig.keyStoreBackend.delete(alias)

        assertWireFailure(WireErrorCode.DONOR_UNAVAILABLE) {
            backend.begin(generated.handle, operationSpec, rig.caller)
        }
        assertFalse(rig.keyStoreBackend.calls.contains("begin"))
    }

    @Test
    fun lifecycleInputsAndResultsAreDefensive() {
        val rig = PhysicalBackendTestRig()
        val backend = rig.backend()
        val logicalName = testBytes(32, 41)
        val challenge = testBytes(32, 42)
        val command = rig.generateCommand(logicalNameHash = logicalName, challenge = challenge)
        logicalName.fill(0)
        challenge.fill(0)

        val generated = backend.generate(command)
        val expectedChallenge = command.challenge
        val expectedPublicKey = generated.metadata.publicKey
        generated.handle.binding.fill(0)
        generated.metadata.attestationChallenge.fill(0)
        generated.metadata.publicKey.fill(0)
        generated.metadata.certificateChain.forEach { it.fill(0) }

        val metadata = backend.metadata(generated.handle, rig.caller)
        assertContentEquals(expectedChallenge, metadata.attestationChallenge)
        assertContentEquals(expectedPublicKey, metadata.publicKey)
    }

    @Test
    fun beginHandleCreationFailureAbortsDonorOperationAndPreservesCause() {
        val rig = PhysicalBackendTestRig()
        val failingAuthenticator = HandleAuthenticator(HandleMac { ByteArray(31) })
        val backend =
            AndroidWireDonorBackend(
                rig.session(1),
                rig.pair,
                rig.caller,
                rig.repository,
                rig.donor,
                failingAuthenticator,
            )
        val generated = rig.backend().generate(rig.generateCommand())

        val failure =
            kotlin.test.assertFailsWith<org.matrix.teesimulator.twophone.WireBackendFailure> {
                backend.begin(generated.handle, operationSpec, rig.caller)
            }
        assertEquals(WireErrorCode.DONOR_UNAVAILABLE, failure.code)
        assertEquals(1, rig.keyStoreBackend.operations.single().abortCount)
    }
}
