package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireOperationHandle

class HandleAuthenticatorTest {
    private val pair = PairIdentity("target-pinned-certificate", "donor-pinned-certificate")
    private val caller = WireCallerIdentity("signer-sha256", "attestation-application-id")
    private val scope = HandleScope(pair, caller)
    private val keyId = uuid(1)
    private val operationId = uuid(2)
    private val sessionId = bytes(32, 3)
    private val signerKey = bytes(32, 4)
    private val authenticator = HandleAuthenticator(JceHandleMac(signerKey))

    @Test
    fun scopeCopiesStablePairAndCallerIdentity() {
        assertEquals(pair, scope.pair)
        assertEquals(caller, scope.caller)
        assertNotSame(pair, scope.pair)
        assertNotSame(caller, scope.caller)
        assertEquals(scope, HandleScope(pair.copy(), caller.copy()))
        assertEquals(scope.hashCode(), HandleScope(pair.copy(), caller.copy()).hashCode())
    }

    @Test
    fun keyHandleCanonicalInputIsLengthPrefixedDomainScopeAndKeyId() {
        val mac = RecordingHandleMac()
        val handle = HandleAuthenticator(mac).createKeyHandle(scope, keyId)

        assertEquals(keyId, handle.id)
        assertFieldsEqual(
            listOf(
                "teesim-key-handle-v1".encodeToByteArray(),
                pair.targetPin.encodeToByteArray(),
                pair.donorPin.encodeToByteArray(),
                caller.signingCertificateDigest.encodeToByteArray(),
                caller.attestationApplicationIdDigest.encodeToByteArray(),
                keyId.bytes(),
            ),
            actual = decodeLengthPrefixed(mac.inputs.single()),
        )
    }

    @Test
    fun operationHandleCanonicalInputIsLengthPrefixedDomainSessionScopeAndIds() {
        val mac = RecordingHandleMac()
        val handle =
            HandleAuthenticator(mac).createOperationHandle(sessionId, scope, operationId, keyId)

        assertEquals(operationId, handle.id)
        assertEquals(keyId, handle.keyId)
        assertFieldsEqual(
            listOf(
                "teesim-operation-handle-v1".encodeToByteArray(),
                sessionId,
                pair.targetPin.encodeToByteArray(),
                pair.donorPin.encodeToByteArray(),
                caller.signingCertificateDigest.encodeToByteArray(),
                caller.attestationApplicationIdDigest.encodeToByteArray(),
                operationId.bytes(),
                keyId.bytes(),
            ),
            actual = decodeLengthPrefixed(mac.inputs.single()),
        )
    }

    @Test
    fun keyHandleBindsPairCallerAndKeyId() {
        val handle = authenticator.createKeyHandle(scope, keyId)

        assertTrue(authenticator.verifyKeyHandle(scope, keyId, handle))
        listOf(
                HandleScope(pair.copy(targetPin = "other-target"), caller),
                HandleScope(pair.copy(donorPin = "other-donor"), caller),
                HandleScope(pair, caller.copy(signingCertificateDigest = "other-signer")),
                HandleScope(pair, caller.copy(attestationApplicationIdDigest = "other-application")),
            )
            .forEach { changedScope ->
                assertFalse(authenticator.verifyKeyHandle(changedScope, keyId, handle))
            }
        assertFalse(authenticator.verifyKeyHandle(scope, uuid(10), handle))
        assertFalse(
            authenticator.verifyKeyHandle(scope, keyId, WireKeyHandle(uuid(11), handle.binding))
        )
        assertFalse(
            authenticator.verifyKeyHandle(
                scope,
                keyId,
                WireKeyHandle(handle.id, handle.binding.mutated()),
            )
        )
    }

    @Test
    fun operationHandleAdditionallyBindsSessionOperationAndKeyIds() {
        val handle = authenticator.createOperationHandle(sessionId, scope, operationId, keyId)

        assertTrue(
            authenticator.verifyOperationHandle(sessionId, scope, operationId, keyId, handle)
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId.mutated(),
                scope,
                operationId,
                keyId,
                handle,
            )
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId,
                HandleScope(pair.copy(targetPin = "other-target"), caller),
                operationId,
                keyId,
                handle,
            )
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId,
                HandleScope(pair, caller.copy(signingCertificateDigest = "other-signer")),
                operationId,
                keyId,
                handle,
            )
        )
        assertFalse(authenticator.verifyOperationHandle(sessionId, scope, uuid(12), keyId, handle))
        assertFalse(
            authenticator.verifyOperationHandle(sessionId, scope, operationId, uuid(13), handle)
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId,
                scope,
                operationId,
                keyId,
                WireOperationHandle(uuid(14), handle.keyId, handle.binding),
            )
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId,
                scope,
                operationId,
                keyId,
                WireOperationHandle(handle.id, uuid(15), handle.binding),
            )
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId,
                scope,
                operationId,
                keyId,
                WireOperationHandle(handle.id, handle.keyId, handle.binding.mutated()),
            )
        )
    }

    @Test
    fun keyAndOperationDomainsCannotCross() {
        val sharedId = uuid(20)
        val keyHandle = authenticator.createKeyHandle(scope, sharedId)
        val operationHandle =
            authenticator.createOperationHandle(sessionId, scope, sharedId, sharedId)

        assertFalse(
            authenticator.verifyKeyHandle(
                scope,
                sharedId,
                WireKeyHandle(sharedId, operationHandle.binding),
            )
        )
        assertFalse(
            authenticator.verifyOperationHandle(
                sessionId,
                scope,
                sharedId,
                sharedId,
                WireOperationHandle(sharedId, sharedId, keyHandle.binding),
            )
        )
    }

    @Test
    fun reconstructedAuthenticatorsUsingTheSameSignerProduceIdenticalHandles() {
        val first = HandleAuthenticator(JceHandleMac(signerKey))
        val reconstructed = HandleAuthenticator(JceHandleMac(signerKey.copyOf()))

        val firstKey = first.createKeyHandle(scope, keyId)
        val reconstructedKey = reconstructed.createKeyHandle(scope, keyId)
        assertEquals(firstKey.id, reconstructedKey.id)
        assertContentEquals(firstKey.binding, reconstructedKey.binding)
        assertTrue(reconstructed.verifyKeyHandle(scope, keyId, firstKey))

        val firstOperation = first.createOperationHandle(sessionId, scope, operationId, keyId)
        val reconstructedOperation =
            reconstructed.createOperationHandle(sessionId, scope, operationId, keyId)
        assertEquals(firstOperation.id, reconstructedOperation.id)
        assertEquals(firstOperation.keyId, reconstructedOperation.keyId)
        assertContentEquals(firstOperation.binding, reconstructedOperation.binding)
        assertTrue(
            reconstructed.verifyOperationHandle(
                sessionId,
                scope,
                operationId,
                keyId,
                firstOperation,
            )
        )
    }

    @Test
    fun verificationStillSignsWhenPresentedIdsAreWrong() {
        val mac = CountingHandleMac(JceHandleMac(signerKey))
        val countingAuthenticator = HandleAuthenticator(mac)
        val keyHandle = countingAuthenticator.createKeyHandle(scope, keyId)
        val operationHandle =
            countingAuthenticator.createOperationHandle(sessionId, scope, operationId, keyId)
        mac.calls = 0

        countingAuthenticator.verifyKeyHandle(
            scope,
            keyId,
            WireKeyHandle(uuid(30), keyHandle.binding),
        )
        countingAuthenticator.verifyOperationHandle(
            sessionId,
            scope,
            operationId,
            keyId,
            WireOperationHandle(uuid(31), uuid(32), operationHandle.binding),
        )

        assertEquals(2, mac.calls)
    }

    @Test
    fun requiresThirtyTwoByteSessionsAndMacOutputs() {
        listOf(ByteArray(31), ByteArray(33)).forEach { invalidSessionId ->
            assertFailsWith<HandleAuthenticatorException.InvalidSessionId> {
                authenticator.createOperationHandle(invalidSessionId, scope, operationId, keyId)
            }
        }
        listOf(ByteArray(31), ByteArray(33)).forEach { invalidOutput ->
            assertFailsWith<HandleAuthenticatorException.InvalidMacOutput> {
                HandleAuthenticator(HandleMac { invalidOutput }).createKeyHandle(scope, keyId)
            }
        }
    }

    private fun decodeLengthPrefixed(input: ByteArray): List<ByteArray> {
        val fields = mutableListOf<ByteArray>()
        DataInputStream(ByteArrayInputStream(input)).use { stream ->
            while (stream.available() > 0) {
                val size = stream.readInt()
                assertTrue(size >= 0)
                fields += ByteArray(size).also(stream::readFully)
            }
        }
        return fields
    }

    private fun assertFieldsEqual(expected: List<ByteArray>, actual: List<ByteArray>) {
        assertEquals(expected.size, actual.size)
        expected.zip(actual).forEach { (expectedField, actualField) ->
            assertContentEquals(expectedField, actualField)
        }
    }

    private fun UUID.bytes(): ByteArray =
        ByteArray(16).also { bytes ->
            java.nio.ByteBuffer.wrap(bytes)
                .putLong(mostSignificantBits)
                .putLong(leastSignificantBits)
        }

    private fun ByteArray.mutated(): ByteArray =
        copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

    private class RecordingHandleMac : HandleMac {
        val inputs = mutableListOf<ByteArray>()

        override fun sign(input: ByteArray): ByteArray {
            inputs += input.copyOf()
            return ByteArray(32)
        }
    }

    private class CountingHandleMac(private val delegate: HandleMac) : HandleMac {
        var calls = 0

        override fun sign(input: ByteArray): ByteArray {
            calls += 1
            return delegate.sign(input)
        }
    }

    private class JceHandleMac(keyBytes: ByteArray) : HandleMac {
        private val key = SecretKeySpec(keyBytes.copyOf(), "HmacSHA256")

        override fun sign(input: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(key) }.doFinal(input)
    }

    private companion object {
        fun uuid(value: Long) = UUID(0, value)

        fun bytes(size: Int, seed: Int) = ByteArray(size) { (seed + it).toByte() }
    }
}
