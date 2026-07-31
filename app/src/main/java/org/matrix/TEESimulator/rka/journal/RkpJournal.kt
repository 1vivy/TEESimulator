package org.matrix.TEESimulator.rka.journal

import java.security.MessageDigest
import java.security.SecureRandom
import org.matrix.TEESimulator.rka.broker.RkpKeyCount

enum class RkpJournalState {
    RKP_KEY_GENERATING,
    RKP_KEY_RECORDED,
    CSR_PREPARED,
    CSR_POSTING,
    POST_AMBIGUOUS,
    RKP_CERTIFIED,
    APP_KEY_GENERATING,
    APP_KEY_RECORDED,
    EXPOSED,
    TERMINAL,
    DELETE,
    QUARANTINED,
}

class RkpBatchId private constructor(private val value: ByteArray) {
    fun copyBytes(): ByteArray = value.copyOf()

    internal fun matches(other: RkpBatchId): Boolean = value.contentEquals(other.value)

    override fun toString(): String = "RkpBatchId(redacted)"

    companion object {
        fun fresh(random: SecureRandom = SecureRandom()): RkpBatchId =
            RkpBatchId(ByteArray(16).also(random::nextBytes))

        internal fun from(bytes: ByteArray): RkpBatchId {
            require(bytes.size == 16)
            return RkpBatchId(bytes.copyOf())
        }
    }
}

class RkpOpaqueHandle private constructor(private val value: ByteArray) {
    fun copyBytes(): ByteArray = value.copyOf()

    override fun toString(): String = "RkpOpaqueHandle(redacted)"

    internal fun matches(other: RkpOpaqueHandle): Boolean = value.contentEquals(other.value)

    companion object {
        internal fun derive(
            batchId: RkpBatchId,
            order: Int,
            publicHash: ByteArray,
            spkiHash: ByteArray,
        ): RkpOpaqueHandle {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("RKA-RKP-HANDLE-v1\u0000".toByteArray())
            digest.update(batchId.copyBytes())
            digest.update(order.toString().toByteArray())
            digest.update(publicHash)
            digest.update(spkiHash)
            return RkpOpaqueHandle(digest.digest())
        }

        internal fun from(bytes: ByteArray): RkpOpaqueHandle {
            require(bytes.size == 32)
            return RkpOpaqueHandle(bytes.copyOf())
        }
    }
}

data class RkpJournalEntry(
    val order: Int,
    private val publicKey: ByteArray,
    private val spkiDer: ByteArray,
    private val publicHash: ByteArray,
    private val spkiHash: ByteArray,
    val handle: RkpOpaqueHandle,
) {
    fun copyPublicKey(): ByteArray = publicKey.copyOf()

    fun copySpkiDer(): ByteArray = spkiDer.copyOf()

    fun copyPublicHash(): ByteArray = publicHash.copyOf()

    fun copySpkiHash(): ByteArray = spkiHash.copyOf()

    override fun toString(): String = "RkpJournalEntry(order=$order, redacted)"
}

data class RkpJournalRecord(
    val batchId: RkpBatchId,
    val state: RkpJournalState,
    val count: Int,
    val identity: RkpIrpcIdentity,
    val entries: List<RkpJournalEntry>,
) {
    init {
        require(count in 1..RkpKeyCount.MAX)
        require(entries.isEmpty() || entries.size == count)
        require(
            state == RkpJournalState.RKP_KEY_GENERATING ||
                state == RkpJournalState.QUARANTINED ||
                entries.isNotEmpty()
        )
        require(entries.map { it.order } == entries.indices.toList())
        require(entries.map { it.copyPublicHash().hex() }.distinct().size == entries.size)
        require(entries.map { it.copySpkiHash().hex() }.distinct().size == entries.size)
        require(entries.map { it.handle.copyBytes().hex() }.distinct().size == entries.size)
    }
}

interface RkpJournalStore {
    fun read(): ByteArray?

    fun replace(value: ByteArray)
}

class RkpJournal(private val store: RkpJournalStore) {
    private var clearBrokerBlobs: (() -> Unit)? = null
    private var resolveBrokerBlob: ((ByteArray) -> Boolean)? = null

    fun begin(
        count: RkpKeyCount,
        identity: RkpIrpcIdentity,
        batchId: RkpBatchId = RkpBatchId.fresh(),
    ): RkpJournalRecord {
        check(store.read() == null) { "active batch exists" }
        return persist(
            RkpJournalRecord(
                batchId,
                RkpJournalState.RKP_KEY_GENERATING,
                count.value,
                identity,
                emptyList(),
            )
        )
    }

    internal fun deriveEntries(
        generating: RkpJournalRecord,
        publicKeys: List<Pair<ByteArray, ByteArray>>,
    ): List<RkpJournalEntry> {
        require(generating.state == RkpJournalState.RKP_KEY_GENERATING)
        requireCurrent(generating)
        require(publicKeys.size == generating.count)
        return publicKeys.mapIndexed { order, (macedPublicKey, spkiDer) ->
            val hash = sha256(macedPublicKey)
            val spkiHash = sha256(spkiDer)
            RkpJournalEntry(
                order,
                macedPublicKey,
                spkiDer,
                hash,
                spkiHash,
                RkpOpaqueHandle.derive(generating.batchId, order, hash, spkiHash),
            )
        }
    }

    internal fun record(
        generating: RkpJournalRecord,
        entries: List<RkpJournalEntry>,
        resolveBlob: (ByteArray) -> Boolean = { false },
        clearBlobs: () -> Unit,
    ): RkpJournalRecord {
        requireCurrent(generating)
        require(entries.size == generating.count)
        try {
            val recorded =
                generating.copy(state = RkpJournalState.RKP_KEY_RECORDED, entries = entries)
            persist(recorded)
            clearBrokerBlobs = clearBlobs
            resolveBrokerBlob = resolveBlob
            return recorded
        } catch (failure: RuntimeException) {
            clearBlobs()
            throw failure
        }
    }

    fun transition(expected: RkpJournalRecord, next: RkpJournalState): RkpJournalRecord {
        requireCurrent(expected)
        require(
            next == successor(expected.state) ||
                expected.state == RkpJournalState.CSR_POSTING &&
                    next == RkpJournalState.RKP_CERTIFIED
        ) {
            "invalid journal transition"
        }
        val transitioned = persist(expected.copy(state = next))
        if (next == RkpJournalState.DELETE) clearRetainedBlobs()
        return transitioned
    }

    internal fun quarantine(expected: RkpJournalRecord): RkpJournalRecord {
        requireCurrent(expected)
        require(
            expected.state == RkpJournalState.RKP_KEY_GENERATING ||
                expected.state == RkpJournalState.APP_KEY_GENERATING
        )
        clearRetainedBlobs()
        return persist(expected.copy(state = RkpJournalState.QUARANTINED))
    }

    fun quarantineCurrent(): RkpJournalRecord? {
        val current = store.read()?.let(RkpJournalCodec::decode) ?: return null
        clearRetainedBlobs()
        return persist(current.copy(state = RkpJournalState.QUARANTINED))
    }

    fun quarantineHandles(handles: List<ByteArray>): Boolean {
        val current = store.read()?.let(RkpJournalCodec::decode) ?: return false
        val expected = current.entries.map { it.handle.copyBytes() }
        val exact =
            handles.size == expected.size &&
                handles.zip(expected).all { (actual, retained) ->
                    actual.contentEquals(retained) && resolveBrokerBlob?.invoke(actual) == true
                }
        clearRetainedBlobs()
        persist(current.copy(state = RkpJournalState.QUARANTINED))
        return exact
    }

    fun recover(): RkpJournalRecord? {
        val record = store.read()?.let(RkpJournalCodec::decode) ?: return null
        val recovery =
            when (record.state) {
                RkpJournalState.RKP_KEY_GENERATING,
                RkpJournalState.APP_KEY_GENERATING -> RkpJournalState.QUARANTINED
                RkpJournalState.CSR_POSTING -> RkpJournalState.POST_AMBIGUOUS
                else -> return record
            }
        clearRetainedBlobs()
        return persist(record.copy(state = recovery))
    }

    private fun persist(record: RkpJournalRecord): RkpJournalRecord {
        store.replace(RkpJournalCodec.encode(record))
        return record
    }

    private fun requireCurrent(expected: RkpJournalRecord) {
        val current = store.read()?.let(RkpJournalCodec::decode)
        require(
            current != null &&
                current.batchId.matches(expected.batchId) &&
                current.state == expected.state &&
                current.count == expected.count &&
                current.identity == expected.identity
        ) {
            "stale or wrong batch"
        }
    }

    private fun clearRetainedBlobs() {
        clearBrokerBlobs?.invoke()
        clearBrokerBlobs = null
        resolveBrokerBlob = null
    }

    private fun successor(state: RkpJournalState): RkpJournalState =
        when (state) {
            RkpJournalState.RKP_KEY_GENERATING -> RkpJournalState.RKP_KEY_RECORDED
            RkpJournalState.RKP_KEY_RECORDED -> RkpJournalState.CSR_PREPARED
            RkpJournalState.CSR_PREPARED -> RkpJournalState.CSR_POSTING
            RkpJournalState.CSR_POSTING -> RkpJournalState.POST_AMBIGUOUS
            RkpJournalState.RKP_CERTIFIED -> RkpJournalState.APP_KEY_GENERATING
            RkpJournalState.APP_KEY_GENERATING -> RkpJournalState.APP_KEY_RECORDED
            RkpJournalState.APP_KEY_RECORDED -> RkpJournalState.EXPOSED
            RkpJournalState.EXPOSED -> RkpJournalState.TERMINAL
            RkpJournalState.TERMINAL -> RkpJournalState.DELETE
            RkpJournalState.POST_AMBIGUOUS,
            RkpJournalState.DELETE,
            RkpJournalState.QUARANTINED -> throw IllegalStateException("terminal journal state")
        }
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
