package org.matrix.TEESimulator.rka.bridge

import java.io.Closeable
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Semaphore

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

    internal val known =
        setOf(PUBLIC_KEY_REQUEST, PUBLIC_KEY_RESPONSE, UPDATE_REQUEST, PUBLIC_RESULT, CANCEL, ERROR)
}

@JvmInline value class RequestId(val value: Long)

class PublicBytes private constructor(bytes: ByteArray) {
    private val value = bytes.copyOf()

    fun copyBytes(): ByteArray = value.copyOf()

    internal val size: Int
        get() = value.size

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

class Hash32 private constructor(bytes: ByteArray) {
    private val value = bytes.copyOf()

    fun copyBytes(): ByteArray = value.copyOf()

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

class NetworkHandle private constructor(bytes: ByteArray) {
    private val value = bytes.copyOf()

    fun copyBytes(): ByteArray = value.copyOf()

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

sealed class BridgeMessage {
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
        }

        fun publicKeyHashes(): List<Hash32> = values.map { Hash32.of(it.copyBytes()) }

        override fun toString(): String =
            "PublicKeyResponse(requestId=$requestId,csrLength=${publicCsr.size},hashCount=${values.size})"
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
    }

    class PublicResult(
        override val requestId: RequestId,
        val networkHandle: NetworkHandle,
        val publicSpki: PublicBytes,
        certificateChain: List<PublicBytes>,
    ) : BridgeMessage() {
        private val chain =
            certificateChain.map {
                PublicBytes.of(it.copyBytes(), BridgeLimits.MAX_CERTIFICATE_BYTES)
            }

        init {
            require(publicSpki.size in 1..BridgeLimits.MAX_CERTIFICATE_BYTES)
            require(chain.size in 1..BridgeLimits.MAX_CHAIN_CERTIFICATES)
        }

        fun certificateChain(): List<PublicBytes> =
            chain.map { PublicBytes.of(it.copyBytes(), BridgeLimits.MAX_CERTIFICATE_BYTES) }

        override fun toString(): String =
            "PublicResult(requestId=$requestId,spkiLength=${publicSpki.size},certificateCount=${chain.size})"
    }

    class Cancel(override val requestId: RequestId) : BridgeMessage() {
        override fun equals(other: Any?): Boolean = other is Cancel && requestId == other.requestId

        override fun hashCode(): Int = requestId.hashCode()

        override fun toString(): String = "Cancel(requestId=$requestId)"
    }

    class Error(
        override val requestId: RequestId,
        val code: BridgeErrorCode,
        val detailHash: Hash32,
    ) : BridgeMessage() {
        override fun toString(): String = "Error(requestId=$requestId,code=$code,detail=redacted)"
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

    data object SocketPolicy : BridgeError()

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
