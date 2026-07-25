package org.matrix.teesimulator.twophone

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

enum class ProtocolVersion {
    V1
}

enum class Method {
    GENERATE,
    IMPORT,
    GET_METADATA,
    DELETE,
    BEGIN,
    UPDATE_AAD,
    UPDATE,
    FINISH,
    ABORT,
}

data class PairIdentity(val targetPin: String, val donorPin: String)

data class CallerIdentity(
    val uid: Int,
    val signingCertificateDigest: String,
    val attestationApplicationIdDigest: String,
)

class CanonicalBody private constructor(val encoded: ByteArray) {
    val sha256: ByteArray
        get() = encoded.sha256()

    companion object {
        private const val MAX_FIELDS = 64
        private const val MAX_NAME_BYTES = 128
        private const val MAX_VALUE_BYTES = 1024 * 1024
        private const val MAX_BODY_BYTES = 2 * 1024 * 1024

        fun of(vararg fields: Pair<String, ByteArray>): CanonicalBody {
            require(fields.size <= MAX_FIELDS)
            require(fields.map { it.first }.distinct().size == fields.size)
            val output = ByteArrayOutputStream()
            DataOutputStream(output).use { stream ->
                stream.writeInt(fields.size)
                fields
                    .sortedBy { it.first }
                    .forEach { (name, value) ->
                        val nameBytes = name.encodeToByteArray()
                        require(nameBytes.size <= MAX_NAME_BYTES)
                        require(value.size <= MAX_VALUE_BYTES)
                        stream.writeInt(nameBytes.size)
                        stream.write(nameBytes)
                        stream.writeInt(value.size)
                        stream.write(value)
                    }
            }
            require(output.size() <= MAX_BODY_BYTES)
            return CanonicalBody(output.toByteArray())
        }
    }
}

data class RequestId(val bytes: ByteArray) {
    init {
        require(bytes.size == 16)
    }
}

data class Envelope(
    val version: ProtocolVersion,
    val sessionId: ByteArray,
    val clientNonce: ByteArray,
    val serverNonce: ByteArray,
    val sequence: ULong,
    val requestId: RequestId,
    val bodyHash: ByteArray,
    val method: Method,
    val deadline: Instant,
    val body: CanonicalBody,
)

sealed class ProtocolException(message: String) : RuntimeException(message) {
    class OldSession : ProtocolException("old or foreign session")

    class SequenceDuplicate : ProtocolException("sequence already consumed")

    class SequenceGap : ProtocolException("sequence is not exact")

    class SequenceOverflow : ProtocolException("uint64 sequence exhausted")

    class RequestIdBodyMismatch : ProtocolException("request id reused with changed body")

    class InvalidBodyHash : ProtocolException("body hash mismatch")

    class DeadlineExceeded : ProtocolException("bounded deadline exceeded")

    class WrongPair : ProtocolException("pinned TLS identity pair mismatch")

    class WrongCaller : ProtocolException("caller identity mismatch")
}

class Session private constructor(val target: Direction, val donor: Direction) {
    companion object {
        fun establish(pair: PairIdentity, clientNonce: ByteArray, serverNonce: ByteArray): Session {
            require(clientNonce.size == 32 && serverNonce.size == 32)
            val sessionId =
                canonicalBytes(
                        "two-phone-v1".encodeToByteArray(),
                        pair.targetPin.encodeToByteArray(),
                        pair.donorPin.encodeToByteArray(),
                        clientNonce,
                        serverNonce,
                    )
                    .sha256()
            return Session(
                Direction(sessionId, clientNonce.copyOf(), serverNonce.copyOf(), pair, true),
                Direction(sessionId, clientNonce.copyOf(), serverNonce.copyOf(), pair, false),
            )
        }
    }
}

class Direction
internal constructor(
    private val sessionId: ByteArray,
    private val clientNonce: ByteArray,
    private val serverNonce: ByteArray,
    private val pair: PairIdentity,
    private val sender: Boolean,
) {
    private var nextSequence = 0uL
    private val responses = ConcurrentHashMap<String, CachedResponse>()

    @Synchronized
    fun nextRequest(method: Method, body: CanonicalBody, deadline: Instant): Envelope {
        check(sender)
        val sequence = nextSequence
        if (sequence == ULong.MAX_VALUE) {
            nextSequence = ULong.MAX_VALUE
        } else {
            nextSequence++
        }
        if (sequence == ULong.MAX_VALUE && exhausted) throw ProtocolException.SequenceOverflow()
        if (sequence == ULong.MAX_VALUE) exhausted = true
        return Envelope(
            ProtocolVersion.V1,
            sessionId.copyOf(),
            clientNonce.copyOf(),
            serverNonce.copyOf(),
            sequence,
            RequestId(ByteArray(16).also(SecureRandom()::nextBytes)),
            body.sha256,
            method,
            deadline,
            body,
        )
    }

    private var exhausted = false

    @Synchronized
    fun forceNextSequenceForTest(value: ULong) {
        nextSequence = value
        exhausted = false
    }

    @Synchronized
    fun accept(
        request: Envelope,
        presentedPair: PairIdentity,
        caller: CallerIdentity,
        now: Instant,
    ) {
        validateCommon(request, presentedPair, now)
        validateSequence(request.sequence)
    }

    @Synchronized
    fun dispatch(
        request: Envelope,
        presentedPair: PairIdentity,
        caller: CallerIdentity,
        now: Instant,
        handler: (Method, CanonicalBody, CallerIdentity) -> ByteArray,
    ): ByteArray {
        validateCommon(request, presentedPair, now, validateBody = false)
        val id = request.requestId.bytes.toHex()
        responses[id]?.let {
            if (
                !MessageDigest.isEqual(it.bodyHash, request.bodyHash) ||
                    !MessageDigest.isEqual(request.bodyHash, request.body.sha256)
            ) {
                throw ProtocolException.RequestIdBodyMismatch()
            }
            return it.response.copyOf()
        }
        if (!MessageDigest.isEqual(request.bodyHash, request.body.sha256)) {
            throw ProtocolException.InvalidBodyHash()
        }
        validateSequence(request.sequence)
        val response = handler(request.method, request.body, caller)
        responses[id] = CachedResponse(request.bodyHash.copyOf(), response.copyOf())
        return response
    }

    private fun validateCommon(
        request: Envelope,
        presentedPair: PairIdentity,
        now: Instant,
        validateBody: Boolean = true,
    ) {
        check(!sender)
        if (presentedPair != pair) throw ProtocolException.WrongPair()
        if (
            !MessageDigest.isEqual(request.sessionId, sessionId) ||
                !MessageDigest.isEqual(request.clientNonce, clientNonce) ||
                !MessageDigest.isEqual(request.serverNonce, serverNonce)
        ) {
            throw ProtocolException.OldSession()
        }
        if (now.isAfter(request.deadline)) throw ProtocolException.DeadlineExceeded()
        if (validateBody && !MessageDigest.isEqual(request.bodyHash, request.body.sha256)) {
            throw ProtocolException.InvalidBodyHash()
        }
    }

    private fun validateSequence(sequence: ULong) {
        when {
            sequence < nextSequence -> throw ProtocolException.SequenceDuplicate()
            sequence > nextSequence -> throw ProtocolException.SequenceGap()
            sequence == ULong.MAX_VALUE -> {
                if (exhausted) throw ProtocolException.SequenceOverflow()
                exhausted = true
            }
            else -> nextSequence++
        }
    }

    private data class CachedResponse(val bodyHash: ByteArray, val response: ByteArray)
}

interface PinnedTransport {
    val localIdentity: String
    val expectedPeerIdentity: String

    fun exchange(request: Envelope): ByteArray
}

class MutableClock(private var instant: Instant) {
    fun now(): Instant = instant

    fun deadline(): Instant = instant.plusSeconds(30)

    fun afterDeadline(): Instant = instant.plusSeconds(31)
}

internal fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)

internal fun canonicalBytes(vararg values: ByteArray): ByteArray {
    val output = ByteArrayOutputStream()
    DataOutputStream(output).use { stream ->
        values.forEach {
            stream.writeInt(it.size)
            stream.write(it)
        }
    }
    return output.toByteArray()
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
