package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireOperationHandle

fun interface HandleMac {
    fun sign(input: ByteArray): ByteArray
}

sealed class HandleAuthenticatorException(message: String) : RuntimeException(message) {
    class InvalidSessionId : HandleAuthenticatorException("invalid handle session ID")

    class InvalidMacOutput : HandleAuthenticatorException("invalid handle MAC output")
}

class HandleScope(pair: PairIdentity, caller: WireCallerIdentity) {
    private val targetPin = pair.targetPin
    private val donorPin = pair.donorPin
    private val signingCertificateDigest = caller.signingCertificateDigest
    private val attestationApplicationIdDigest = caller.attestationApplicationIdDigest

    val pair: PairIdentity
        get() = PairIdentity(targetPin, donorPin)

    val caller: WireCallerIdentity
        get() = WireCallerIdentity(signingCertificateDigest, attestationApplicationIdDigest)

    internal fun canonicalFields(): List<ByteArray> =
        listOf(
            targetPin.toByteArray(StandardCharsets.UTF_8),
            donorPin.toByteArray(StandardCharsets.UTF_8),
            signingCertificateDigest.toByteArray(StandardCharsets.UTF_8),
            attestationApplicationIdDigest.toByteArray(StandardCharsets.UTF_8),
        )

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is HandleScope &&
                targetPin == other.targetPin &&
                donorPin == other.donorPin &&
                signingCertificateDigest == other.signingCertificateDigest &&
                attestationApplicationIdDigest == other.attestationApplicationIdDigest)

    override fun hashCode(): Int {
        var result = targetPin.hashCode()
        result = 31 * result + donorPin.hashCode()
        result = 31 * result + signingCertificateDigest.hashCode()
        result = 31 * result + attestationApplicationIdDigest.hashCode()
        return result
    }
}

class HandleAuthenticator(private val mac: HandleMac) {
    fun createKeyHandle(scope: HandleScope, keyId: UUID): WireKeyHandle =
        WireKeyHandle(keyId, binding(keyInput(scope, keyId)))

    fun verifyKeyHandle(scope: HandleScope, keyId: UUID, handle: WireKeyHandle): Boolean {
        val expectedBinding = binding(keyInput(scope, keyId))
        val idMatches = MessageDigest.isEqual(keyId.bytes(), handle.id.bytes())
        val bindingMatches = MessageDigest.isEqual(expectedBinding, handle.binding)
        return idMatches and bindingMatches
    }

    fun createOperationHandle(
        sessionId: ByteArray,
        scope: HandleScope,
        operationId: UUID,
        keyId: UUID,
    ): WireOperationHandle {
        requireSessionId(sessionId)
        return WireOperationHandle(
            operationId,
            keyId,
            binding(operationInput(sessionId, scope, operationId, keyId)),
        )
    }

    fun verifyOperationHandle(
        sessionId: ByteArray,
        scope: HandleScope,
        operationId: UUID,
        keyId: UUID,
        handle: WireOperationHandle,
    ): Boolean {
        requireSessionId(sessionId)
        val expectedBinding = binding(operationInput(sessionId, scope, operationId, keyId))
        val operationIdMatches = MessageDigest.isEqual(operationId.bytes(), handle.id.bytes())
        val keyIdMatches = MessageDigest.isEqual(keyId.bytes(), handle.keyId.bytes())
        val bindingMatches = MessageDigest.isEqual(expectedBinding, handle.binding)
        return operationIdMatches and keyIdMatches and bindingMatches
    }

    private fun keyInput(scope: HandleScope, keyId: UUID): ByteArray =
        canonicalInput(KEY_HANDLE_DOMAIN, scope.canonicalFields() + keyId.bytes())

    private fun operationInput(
        sessionId: ByteArray,
        scope: HandleScope,
        operationId: UUID,
        keyId: UUID,
    ): ByteArray =
        canonicalInput(
            OPERATION_HANDLE_DOMAIN,
            listOf(sessionId.copyOf()) +
                scope.canonicalFields() +
                operationId.bytes() +
                keyId.bytes(),
        )

    private fun binding(input: ByteArray): ByteArray {
        val output = mac.sign(input)
        if (output.size != HMAC_SHA_256_BYTES) {
            throw HandleAuthenticatorException.InvalidMacOutput()
        }
        return output
    }

    private fun requireSessionId(sessionId: ByteArray) {
        if (sessionId.size != SESSION_ID_BYTES) {
            throw HandleAuthenticatorException.InvalidSessionId()
        }
    }

    private fun canonicalInput(domain: String, fields: List<ByteArray>): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeLengthPrefixed(domain.toByteArray(StandardCharsets.US_ASCII))
            fields.forEach { field -> stream.writeLengthPrefixed(field) }
        }
        return output.toByteArray()
    }

    private fun DataOutputStream.writeLengthPrefixed(bytes: ByteArray) {
        writeInt(bytes.size)
        write(bytes)
    }

    private fun UUID.bytes(): ByteArray =
        ByteBuffer.allocate(UUID_BYTES)
            .putLong(mostSignificantBits)
            .putLong(leastSignificantBits)
            .array()

    private companion object {
        const val HMAC_SHA_256_BYTES = 32
        const val SESSION_ID_BYTES = 32
        const val UUID_BYTES = 16
        const val KEY_HANDLE_DOMAIN = "teesim-key-handle-v1"
        const val OPERATION_HANDLE_DOMAIN = "teesim-operation-handle-v1"
    }
}
