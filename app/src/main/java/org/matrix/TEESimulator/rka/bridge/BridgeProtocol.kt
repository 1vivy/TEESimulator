package org.matrix.TEESimulator.rka.bridge

import java.io.Closeable
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean

/** Frozen Task-7/Task-8 broker bridge contract. This is not the public RKA v2 wire protocol. */
object BridgeLimits {
    const val MAGIC = 0x524b4231 // "RKB1"
    const val VERSION = 1
    const val HEADER_BYTES = 24
    const val MAX_FRAME_BYTES = 1_048_576
    const val MAX_UPDATE_BYTES = 65_536
    const val MAX_TOTAL_INPUT_BYTES = 1_048_576
    const val MAX_IN_FLIGHT = 4
    const val MAX_QUEUED = 4
    const val DEADLINE_MILLIS = 5_000L
    const val MAX_PUBLIC_KEYS = 20
    const val MAX_CHAIN_CERTIFICATES = 20
    const val MAX_CERTIFICATE_BYTES = 65_536
    const val MAX_CHAIN_BYTES = 524_288
}

enum class BridgeDirection(val wire: Int) {
    SIDECAR_TO_BROKER(1),
    BROKER_TO_SIDECAR(2),
}

object BridgeTag {
    const val PUBLIC_KEY_REQUEST = 1
    const val PUBLIC_KEY_RESPONSE = 2
    const val UPDATE_REQUEST = 3
    const val PUBLIC_RESULT = 4
    const val CANCEL = 5
    const val ERROR = 6
    const val CANDIDATE_COMMAND = 7
    const val CANDIDATE_REPLY = 8

    internal val known =
        setOf(
            PUBLIC_KEY_REQUEST,
            PUBLIC_KEY_RESPONSE,
            UPDATE_REQUEST,
            PUBLIC_RESULT,
            CANCEL,
            ERROR,
            CANDIDATE_COMMAND,
            CANDIDATE_REPLY,
        )
}

enum class BridgeExchangeRole(val direction: BridgeDirection, internal val tags: Set<Int>) {
    DONOR_REQUEST(
        BridgeDirection.SIDECAR_TO_BROKER,
        setOf(BridgeTag.PUBLIC_KEY_REQUEST, BridgeTag.UPDATE_REQUEST, BridgeTag.CANCEL),
    ),
    DONOR_RESPONSE(
        BridgeDirection.BROKER_TO_SIDECAR,
        setOf(
            BridgeTag.PUBLIC_KEY_RESPONSE,
            BridgeTag.PUBLIC_RESULT,
            BridgeTag.CANCEL,
            BridgeTag.ERROR,
        ),
    ),
    CANDIDATE_REQUEST(
        BridgeDirection.BROKER_TO_SIDECAR,
        setOf(
            BridgeTag.PUBLIC_KEY_REQUEST,
            BridgeTag.UPDATE_REQUEST,
            BridgeTag.CANCEL,
            BridgeTag.CANDIDATE_COMMAND,
        ),
    ),
    CANDIDATE_RESPONSE(
        BridgeDirection.SIDECAR_TO_BROKER,
        setOf(
            BridgeTag.PUBLIC_KEY_RESPONSE,
            BridgeTag.PUBLIC_RESULT,
            BridgeTag.CANCEL,
            BridgeTag.ERROR,
            BridgeTag.CANDIDATE_REPLY,
        ),
    ),
}

enum class CandidateBridgeOperation(val wire: Int) {
    GENERATE(1),
    GET(2),
    LIST(3),
    DELETE(4),
    BEGIN(5),
    UPDATE_AAD(6),
    UPDATE(7),
    FINISH(8),
    ABORT(9),
}

@JvmInline value class RequestId(val value: Long)

class PublicBytes private constructor(bytes: ByteArray) : AutoCloseable {
    private val value = bytes.copyOf()
    private val destroyed = AtomicBoolean()

    fun copyBytes(): ByteArray {
        check(!destroyed.get()) { "public bytes destroyed" }
        return value.copyOf()
    }

    internal val size: Int
        get() {
            check(!destroyed.get()) { "public bytes destroyed" }
            return value.size
        }

    override fun close() {
        if (destroyed.compareAndSet(false, true)) value.fill(0)
    }

    override fun equals(other: Any?): Boolean =
        other is PublicBytes && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "PublicBytes(length=${value.size},redacted)"

    companion object {
        fun of(bytes: ByteArray, maximum: Int): PublicBytes {
            require(maximum in 0..BridgeLimits.MAX_FRAME_BYTES)
            require(bytes.size <= maximum)
            return PublicBytes(bytes)
        }
    }
}

class Hash32 private constructor(bytes: ByteArray) : AutoCloseable {
    private val value = bytes.copyOf()
    private val destroyed = AtomicBoolean()

    fun copyBytes(): ByteArray {
        check(!destroyed.get()) { "hash destroyed" }
        return value.copyOf()
    }

    override fun close() {
        if (destroyed.compareAndSet(false, true)) value.fill(0)
    }

    override fun equals(other: Any?): Boolean = other is Hash32 && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "Hash32(redacted)"

    companion object {
        fun of(bytes: ByteArray): Hash32 {
            require(bytes.size == 32)
            return Hash32(bytes)
        }
    }
}

class NetworkHandle private constructor(bytes: ByteArray) : AutoCloseable {
    private val value = bytes.copyOf()
    private val destroyed = AtomicBoolean()

    fun copyBytes(): ByteArray {
        check(!destroyed.get()) { "network handle destroyed" }
        return value.copyOf()
    }

    override fun close() {
        if (destroyed.compareAndSet(false, true)) value.fill(0)
    }

    override fun equals(other: Any?): Boolean =
        other is NetworkHandle && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "NetworkHandle(redacted)"

    companion object {
        fun of(bytes: ByteArray): NetworkHandle {
            require(bytes.size == 16)
            return NetworkHandle(bytes)
        }
    }
}

sealed class BridgeMessage : AutoCloseable {
    abstract val requestId: RequestId

    class PublicKeyRequest(
        override val requestId: RequestId,
        val challenge: PublicBytes,
        val keyCount: Int,
    ) : BridgeMessage() {
        init {
            require(challenge.size in 16..64)
            require(keyCount in 1..BridgeLimits.MAX_PUBLIC_KEYS)
        }

        override fun equals(other: Any?): Boolean =
            other is PublicKeyRequest &&
                requestId == other.requestId &&
                challenge == other.challenge &&
                keyCount == other.keyCount

        override fun hashCode(): Int =
            31 * (31 * requestId.hashCode() + challenge.hashCode()) + keyCount

        override fun toString(): String =
            "PublicKeyRequest(requestId=$requestId,challengeLength=${challenge.size},keyCount=$keyCount)"

        override fun close() {
            challenge.close()
        }
    }

    class PublicKeyResponse(
        override val requestId: RequestId,
        val publicCsr: PublicBytes,
        hashes: List<Hash32>,
    ) : BridgeMessage() {
        private val values = hashes.toList()

        init {
            require(publicCsr.size in 1..BridgeLimits.MAX_FRAME_BYTES)
            require(values.size in 1..BridgeLimits.MAX_PUBLIC_KEYS)
            val encodedSize =
                4L + publicCsr.size + 1L + Math.multiplyExact(values.size.toLong(), 32L)
            require(encodedSize <= BridgeLimits.MAX_FRAME_BYTES)
        }

        fun publicKeyHashes(): List<Hash32> = values.map { Hash32.of(it.copyBytes()) }

        override fun toString(): String =
            "PublicKeyResponse(requestId=$requestId,csrLength=${publicCsr.size},hashCount=${values.size})"

        override fun close() {
            publicCsr.close()
            values.forEach(Hash32::close)
        }
    }

    class UpdateRequest(
        override val requestId: RequestId,
        val operationHandle: NetworkHandle,
        val chunk: PublicBytes,
        val totalInputBytes: Int,
    ) : BridgeMessage() {
        init {
            require(chunk.size <= BridgeLimits.MAX_UPDATE_BYTES)
            require(totalInputBytes in chunk.size..BridgeLimits.MAX_TOTAL_INPUT_BYTES)
        }

        override fun toString(): String =
            "UpdateRequest(requestId=$requestId,chunkLength=${chunk.size},totalInputBytes=$totalInputBytes)"

        override fun close() {
            operationHandle.close()
            chunk.close()
        }
    }

    class PublicResult(
        override val requestId: RequestId,
        val networkHandle: NetworkHandle,
        val publicSpki: PublicBytes,
        certificateChain: List<PublicBytes>,
    ) : BridgeMessage() {
        private val chain = copyBoundedChain(certificateChain)

        init {
            require(publicSpki.size in 1..BridgeLimits.MAX_CERTIFICATE_BYTES)
            require(chain.size in 1..BridgeLimits.MAX_CHAIN_CERTIFICATES)
            val encodedSize =
                16L +
                    4L +
                    publicSpki.size +
                    1L +
                    chain.fold(0L) { sum, certificate -> Math.addExact(sum, 4L + certificate.size) }
            require(encodedSize <= BridgeLimits.MAX_FRAME_BYTES)
        }

        fun certificateChain(): List<PublicBytes> =
            chain.map { PublicBytes.of(it.copyBytes(), BridgeLimits.MAX_CERTIFICATE_BYTES) }

        override fun toString(): String =
            "PublicResult(requestId=$requestId,spkiLength=${publicSpki.size},certificateCount=${chain.size})"

        override fun close() {
            networkHandle.close()
            publicSpki.close()
            chain.forEach(PublicBytes::close)
        }

        private companion object {
            fun copyBoundedChain(source: List<PublicBytes>): List<PublicBytes> {
                require(source.size in 1..BridgeLimits.MAX_CHAIN_CERTIFICATES)
                val total =
                    source.fold(0L) { sum, certificate ->
                        require(certificate.size in 1..BridgeLimits.MAX_CERTIFICATE_BYTES)
                        Math.addExact(sum, certificate.size.toLong())
                    }
                require(total <= BridgeLimits.MAX_CHAIN_BYTES)
                return source.map {
                    PublicBytes.of(it.copyBytes(), BridgeLimits.MAX_CERTIFICATE_BYTES)
                }
            }
        }
    }

    class Cancel(override val requestId: RequestId) : BridgeMessage() {
        override fun equals(other: Any?): Boolean = other is Cancel && requestId == other.requestId

        override fun hashCode(): Int = requestId.hashCode()

        override fun toString(): String = "Cancel(requestId=$requestId)"

        override fun close() = Unit
    }

    class Error(
        override val requestId: RequestId,
        val code: BridgeErrorCode,
        val detailHash: Hash32,
    ) : BridgeMessage() {
        override fun toString(): String = "Error(requestId=$requestId,code=$code,detail=redacted)"

        override fun close() {
            detailHash.close()
        }
    }

    class CandidateCommand(
        override val requestId: RequestId,
        val operation: CandidateBridgeOperation,
        val payload: PublicBytes,
    ) : BridgeMessage() {
        init {
            require(payload.size <= BridgeLimits.MAX_FRAME_BYTES - 5)
        }

        override fun close() = payload.close()

        override fun toString() =
            "CandidateCommand(requestId=$requestId,operation=$operation,payloadLength=${payload.size})"
    }

    class CandidateReply(
        override val requestId: RequestId,
        val operation: CandidateBridgeOperation,
        val payload: PublicBytes,
    ) : BridgeMessage() {
        init {
            require(payload.size <= BridgeLimits.MAX_FRAME_BYTES - 5)
        }

        override fun close() = payload.close()

        override fun toString() =
            "CandidateReply(requestId=$requestId,operation=$operation,payloadLength=${payload.size})"
    }
}

internal data class BridgeCorrelation(
    val requestId: RequestId,
    val expectedTag: Int,
    val generation: Long,
    val worker: Thread,
) {
    fun accepts(message: BridgeMessage): Boolean =
        message.requestId == requestId &&
            (BridgeProtocol.tagOf(message) == expectedTag || message is BridgeMessage.Error)
}

internal object BridgeProtocol {
    fun tagOf(message: BridgeMessage): Int =
        when (message) {
            is BridgeMessage.PublicKeyRequest -> BridgeTag.PUBLIC_KEY_REQUEST
            is BridgeMessage.PublicKeyResponse -> BridgeTag.PUBLIC_KEY_RESPONSE
            is BridgeMessage.UpdateRequest -> BridgeTag.UPDATE_REQUEST
            is BridgeMessage.PublicResult -> BridgeTag.PUBLIC_RESULT
            is BridgeMessage.Cancel -> BridgeTag.CANCEL
            is BridgeMessage.Error -> BridgeTag.ERROR
            is BridgeMessage.CandidateCommand -> BridgeTag.CANDIDATE_COMMAND
            is BridgeMessage.CandidateReply -> BridgeTag.CANDIDATE_REPLY
        }

    fun correlationFor(request: BridgeMessage, generation: Long): BridgeCorrelation {
        val expected =
            when (request) {
                is BridgeMessage.PublicKeyRequest -> BridgeTag.PUBLIC_KEY_RESPONSE
                is BridgeMessage.UpdateRequest -> BridgeTag.PUBLIC_RESULT
                is BridgeMessage.Cancel -> BridgeTag.CANCEL
                is BridgeMessage.CandidateCommand -> BridgeTag.CANDIDATE_REPLY
                else -> throw IllegalArgumentException("message is not a request")
            }
        return BridgeCorrelation(request.requestId, expected, generation, Thread.currentThread())
    }
}

enum class BridgeErrorCode(val wire: Int) {
    INVALID_REQUEST(1),
    POLICY_REJECTED(2),
    CAPACITY(3),
    TRANSPORT(4),
    CANCELLED(5),
    DEADLINE(6),
}

sealed class BridgeError {
    data object BadMagic : BridgeError()

    data object UnsupportedVersion : BridgeError()

    data object WrongDirection : BridgeError()

    data object UnexpectedTag : BridgeError()

    data object UnknownTag : BridgeError()

    data object ReservedBits : BridgeError()

    data object EmptyFrame : BridgeError()

    data object FrameTooLarge : BridgeError()

    data object Truncated : BridgeError()

    data object NonCanonical : BridgeError()

    data object DuplicateCorrelation : BridgeError()

    data object UnknownCorrelation : BridgeError()

    data object Capacity : BridgeError()

    data object QueueSaturated : BridgeError()

    data object DeadlineExceeded : BridgeError()

    data object Cancelled : BridgeError()

    data object PeerDied : BridgeError()

    data object PeerIdentityMismatch : BridgeError()

    data object PeerIdentityChanged : BridgeError()

    data object TrustedStateMissing : BridgeError()

    data object TrustedStateInvalid : BridgeError()

    data object TrustedStateChanged : BridgeError()

    data object SocketPolicy : BridgeError()

    data object SocketCreateDenied : BridgeError()

    data object SocketChownDenied : BridgeError()

    data object SocketChmodDenied : BridgeError()

    data object SocketLabelDenied : BridgeError()

    data object SocketBindDenied : BridgeError()

    data object SocketPathChanged : BridgeError()

    data object SelinuxDenied : BridgeError()

    data object Io : BridgeError()
}

sealed class BridgeResult<out T> {
    class Success<T>(val value: T) : BridgeResult<T>()

    class Failure(val error: BridgeError) : BridgeResult<Nothing>() {
        override fun toString(): String = "BridgeFailure(error=$error,detail=redacted)"
    }
}

class BridgeCapacity(maximum: Int = BridgeLimits.MAX_IN_FLIGHT) {
    private val permits = Semaphore(maximum, true)

    fun acquire(): BridgeResult<Closeable> =
        if (permits.tryAcquire()) {
            BridgeResult.Success(Closeable { permits.release() })
        } else {
            BridgeResult.Failure(BridgeError.Capacity)
        }
}

class BridgeWorkQueue<T>(maximum: Int = BridgeLimits.MAX_QUEUED) {
    private val queue = ArrayBlockingQueue<T>(maximum)

    fun offer(value: T): BridgeResult<Unit> =
        if (queue.offer(value)) {
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.QueueSaturated)
        }

    fun poll(): T? = queue.poll()
}
