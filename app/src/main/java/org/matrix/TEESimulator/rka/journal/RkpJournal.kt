package org.matrix.TEESimulator.rka.journal

import java.nio.ByteBuffer
import java.nio.ByteOrder
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

class RkpCertifiedKey(
    val order: Int,
    val handle: RkpOpaqueHandle,
    publicHash: ByteArray,
    spkiHash: ByteArray,
    chainHash: ByteArray,
    val certificateCount: Int,
) {
    private val publicHash = publicHash.copyOf()
    private val spkiHash = spkiHash.copyOf()
    private val chainHash = chainHash.copyOf()

    init {
        require(order in 0 until RkpKeyCount.MAX)
        require(this.publicHash.size == 32)
        require(this.spkiHash.size == 32)
        require(this.chainHash.size == 32)
        require(certificateCount in 1..20)
    }

    fun copyPublicHash(): ByteArray = publicHash.copyOf()

    fun copySpkiHash(): ByteArray = spkiHash.copyOf()

    fun copyChainHash(): ByteArray = chainHash.copyOf()
}

class RkpCertification(
    val requestId: Long,
    val batchId: RkpBatchId,
    keys: List<RkpCertifiedKey>,
    val profileEpoch: Long,
    activationBindingHash: ByteArray,
) {
    val keys = keys.toList()
    private val activationBindingHash = activationBindingHash.copyOf()

    init {
        require(requestId > 0)
        require(this.keys.size in 1..RkpKeyCount.MAX)
        require(this.keys.map { it.order } == this.keys.indices.toList())
        require(this.activationBindingHash.size == 32)
        require(profileEpoch > 0)
        require(distinct(this.keys.map { it.handle.copyBytes() }))
        require(distinct(this.keys.map(RkpCertifiedKey::copyPublicHash)))
        require(distinct(this.keys.map(RkpCertifiedKey::copySpkiHash)))
        require(distinct(this.keys.map(RkpCertifiedKey::copyChainHash)))
    }

    fun copyActivationBindingHash(): ByteArray = activationBindingHash.copyOf()

    private fun distinct(items: List<ByteArray>): Boolean =
        items.indices.all { index ->
            items.drop(index + 1).none { candidate -> items[index].contentEquals(candidate) }
        }
}

data class RkpJournalRecord(
    val batchId: RkpBatchId,
    val state: RkpJournalState,
    val count: Int,
    val identity: RkpIrpcIdentity,
    val entries: List<RkpJournalEntry>,
    val certification: RkpCertification? = null,
) {
    init {
        require(count in 1..RkpKeyCount.MAX)
        require(entries.isEmpty() || entries.size == count)
        require(
            state == RkpJournalState.RKP_KEY_GENERATING ||
                state == RkpJournalState.QUARANTINED ||
                state == RkpJournalState.TERMINAL ||
                state == RkpJournalState.DELETE ||
                entries.isNotEmpty()
        )
        require(entries.map { it.order } == entries.indices.toList())
        require(entries.map { it.copyPublicHash().hex() }.distinct().size == entries.size)
        require(entries.map { it.copySpkiHash().hex() }.distinct().size == entries.size)
        require(entries.map { it.handle.copyBytes().hex() }.distinct().size == entries.size)
        certification?.let { certified ->
            require(certified.batchId.matches(batchId))
            require(certified.keys.size == entries.size)
            require(
                certified.keys.zip(entries).all { (key, entry) ->
                    key.order == entry.order &&
                        key.handle.matches(entry.handle) &&
                        key.copyPublicHash().contentEquals(entry.copyPublicHash()) &&
                        key.copySpkiHash().contentEquals(entry.copySpkiHash())
                }
            )
        }
    }
}

interface RkpJournalStore {
    fun read(): ByteArray?

    fun replace(value: ByteArray)

    fun clear() {
        throw IllegalStateException("journal clear is unsupported")
    }
}

class RkpJournal(private val store: RkpJournalStore) {
    private var clearBrokerBlobs: (() -> Unit)? = null
    private var resolveBrokerBlob: ((ByteArray) -> Boolean)? = null
    private var withBrokerBlob: ((ByteArray, (ByteArray) -> Unit) -> Boolean)? = null
    private var discardBrokerBlob: ((ByteArray) -> Unit)? = null
    private var brokerBlobDiscarded: ((ByteArray) -> Boolean)? = null
    private var wipeBrokerBlob: ((ByteArray) -> Unit)? = null
    private var brokerBlobWiped: ((ByteArray) -> Boolean)? = null

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
        withBlob: (ByteArray, (ByteArray) -> Unit) -> Boolean = { _, _ -> false },
        discardBlob: ((ByteArray) -> Unit)? = null,
        blobDiscarded: ((ByteArray) -> Boolean)? = null,
        wipeBlob: ((ByteArray) -> Unit)? = null,
        blobWiped: ((ByteArray) -> Boolean)? = null,
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
            withBrokerBlob = withBlob
            discardBrokerBlob = discardBlob
            brokerBlobDiscarded = blobDiscarded
            wipeBrokerBlob = wipeBlob
            brokerBlobWiped = blobWiped
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
        return handles.size == expected.size &&
            handles.zip(expected).all { (actual, retained) -> actual.contentEquals(retained) }
    }

    fun discardRetainedBlob(handle: ByteArray) {
        require(handle.size == 32)
        discardBrokerBlob?.invoke(handle)
    }

    fun retainedBlobDiscarded(handle: ByteArray): Boolean {
        require(handle.size == 32)
        return brokerBlobDiscarded?.invoke(handle) ?: true
    }

    fun wipeRetainedBlob(handle: ByteArray) {
        require(handle.size == 32)
        wipeBrokerBlob?.invoke(handle)
    }

    fun retainedBlobWiped(handle: ByteArray): Boolean {
        require(handle.size == 32)
        return brokerBlobWiped?.invoke(handle) ?: true
    }

    fun completeQuarantine(batchId: ByteArray): Boolean {
        require(batchId.size == 16)
        var current = store.read()?.let(RkpJournalCodec::decode) ?: return true
        if (!current.batchId.copyBytes().contentEquals(batchId)) return true
        current =
            when (current.state) {
                RkpJournalState.QUARANTINED -> transition(current, RkpJournalState.TERMINAL)
                RkpJournalState.TERMINAL -> current
                RkpJournalState.DELETE -> {
                    clearRetainedBlobs()
                    store.clear()
                    return true
                }
                else -> {
                    persist(current.copy(state = RkpJournalState.QUARANTINED))
                    requireNotNull(store.read()?.let(RkpJournalCodec::decode))
                }
            }
        if (current.state == RkpJournalState.QUARANTINED) {
            current = transition(current, RkpJournalState.TERMINAL)
        }
        if (current.state == RkpJournalState.TERMINAL) {
            transition(current, RkpJournalState.DELETE)
            store.clear()
        }
        return store.read() == null
    }

    fun certifyCurrent(certification: RkpCertification): Boolean {
        val current = store.read()?.let(RkpJournalCodec::decode) ?: return false
        val exact =
            current.state == RkpJournalState.CSR_PREPARED &&
                certification.batchId.matches(current.batchId) &&
                certification.keys.size == current.entries.size &&
                certification.keys.zip(current.entries).all { (key, entry) ->
                    key.order == entry.order &&
                        key.handle.matches(entry.handle) &&
                        key.copyPublicHash().contentEquals(entry.copyPublicHash()) &&
                        key.copySpkiHash().contentEquals(entry.copySpkiHash()) &&
                        resolveBrokerBlob?.invoke(key.handle.copyBytes()) == true
                } &&
                certification
                    .copyActivationBindingHash()
                    .contentEquals(task14Binding(certification))
        if (!exact) {
            clearRetainedBlobs()
            persist(current.copy(state = RkpJournalState.QUARANTINED))
            return false
        }
        persist(current.copy(state = RkpJournalState.RKP_CERTIFIED, certification = certification))
        return true
    }

    internal fun withCertifiedBlob(handle: RkpOpaqueHandle, action: (ByteArray) -> Unit): Boolean {
        val current = store.read()?.let(RkpJournalCodec::decode) ?: return false
        val certified = current.certification ?: return false
        if (current.state != RkpJournalState.APP_KEY_GENERATING) return false
        if (certified.keys.none { it.handle.matches(handle) }) return false
        return withBrokerBlob?.invoke(handle.copyBytes(), action) == true
    }

    private fun task14Binding(certification: RkpCertification): ByteArray {
        val batch = MessageDigest.getInstance("SHA-256")
        certification.keys.forEach { key ->
            val lease = MessageDigest.getInstance("SHA-256")
            lease.update("TEESimulator-RS activation v1\u0000".toByteArray())
            lease.update("lease".toByteArray())
            lease.update(
                ByteBuffer.allocate(Long.SIZE_BYTES)
                    .order(ByteOrder.BIG_ENDIAN)
                    .putLong(certification.requestId)
                    .array()
            )
            lease.update(key.copySpkiHash())
            batch.update(lease.digest().copyOf(16))
            batch.update(certification.batchId.copyBytes())
            batch.update(key.order.toByte())
            batch.update(key.copyPublicHash())
            batch.update(key.copySpkiHash())
            batch.update(key.copyChainHash())
            batch.update(key.certificateCount.toByte())
            batch.update(
                ByteBuffer.allocate(Long.SIZE_BYTES)
                    .order(ByteOrder.BIG_ENDIAN)
                    .putLong(certification.profileEpoch)
                    .array()
            )
        }
        return batch.digest()
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
        withBrokerBlob = null
        discardBrokerBlob = null
        brokerBlobDiscarded = null
        wipeBrokerBlob = null
        brokerBlobWiped = null
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
            RkpJournalState.QUARANTINED -> RkpJournalState.TERMINAL
            RkpJournalState.POST_AMBIGUOUS,
            RkpJournalState.DELETE -> throw IllegalStateException("terminal journal state")
        }
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
