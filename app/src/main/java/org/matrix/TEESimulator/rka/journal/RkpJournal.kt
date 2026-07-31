package org.matrix.TEESimulator.rka.journal

import java.security.MessageDigest
import java.security.SecureRandom
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.IrpcGeneratedKey
import org.matrix.TEESimulator.rka.broker.IrpcKeyBatch
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

    companion object {
        internal fun derive(
            batchId: RkpBatchId,
            order: Int,
            publicHash: ByteArray,
        ): RkpOpaqueHandle {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("RKA-RKP-HANDLE-v1\u0000".toByteArray())
            digest.update(batchId.copyBytes())
            digest.update(order.toString().toByteArray())
            digest.update(publicHash)
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
    private val publicHash: ByteArray,
    val handle: RkpOpaqueHandle,
) {
    fun copyPublicKey(): ByteArray = publicKey.copyOf()

    fun copyPublicHash(): ByteArray = publicHash.copyOf()

    override fun toString(): String = "RkpJournalEntry(order=$order, redacted)"
}

data class RkpJournalRecord(
    val batchId: RkpBatchId,
    val state: RkpJournalState,
    val count: Int,
    val irpcVersion: Int,
    val securityLevel: String,
    val curve: String,
    val entries: List<RkpJournalEntry>,
) {
    init {
        require(count in 1..RkpKeyCount.MAX)
        require(irpcVersion == IrpcClient.REQUIRED_VERSION)
        require(securityLevel == "TEE")
        require(curve == "P256")
        require(entries.isEmpty() || entries.size == count)
        require(
            state == RkpJournalState.RKP_KEY_GENERATING ||
                state == RkpJournalState.QUARANTINED ||
                entries.isNotEmpty()
        )
        require(entries.map { it.order } == entries.indices.toList())
        require(entries.map { it.copyPublicHash().hex() }.distinct().size == entries.size)
        require(entries.map { it.handle.copyBytes().hex() }.distinct().size == entries.size)
    }
}

interface RkpJournalStore {
    fun read(): ByteArray?

    fun replace(value: ByteArray)
}

internal class RkpBlobStore {
    private val values = mutableMapOf<String, ByteArray>()

    fun retain(handle: RkpOpaqueHandle, blob: ByteArray) {
        require(values.putIfAbsent(handle.copyBytes().hex(), blob.copyOf()) == null)
    }

    fun deleteAll() {
        values.values.forEach { it.fill(0) }
        values.clear()
    }
}

class RkpJournal
private constructor(private val store: RkpJournalStore, private val blobs: RkpBlobStore) {
    constructor(store: RkpJournalStore) : this(store, RkpBlobStore())

    fun begin(count: RkpKeyCount, batchId: RkpBatchId = RkpBatchId.fresh()): RkpJournalRecord {
        check(store.read() == null) { "active batch exists" }
        return persist(
            RkpJournalRecord(
                batchId,
                RkpJournalState.RKP_KEY_GENERATING,
                count.value,
                3,
                "TEE",
                "P256",
                emptyList(),
            )
        )
    }

    internal fun record(generating: RkpJournalRecord, batch: IrpcKeyBatch): RkpJournalRecord {
        require(generating.state == RkpJournalState.RKP_KEY_GENERATING)
        requireCurrent(generating)
        val publicKeys = batch.publicKeys()
        require(publicKeys.size == generating.count)
        val entries =
            publicKeys.mapIndexed { order, publicKey ->
                val hash = sha256(publicKey)
                RkpJournalEntry(
                    order,
                    publicKey,
                    hash,
                    RkpOpaqueHandle.derive(generating.batchId, order, hash),
                )
            }
        val opaque = batch.opaqueKeys()
        try {
            entries.zip(opaque).forEach { (entry, key) ->
                blobs.retain(entry.handle, key.copyKeyBlob())
            }
            return persist(
                generating.copy(state = RkpJournalState.RKP_KEY_RECORDED, entries = entries)
            )
        } catch (failure: RuntimeException) {
            blobs.deleteAll()
            batch.wipe()
            throw failure
        } finally {
            opaque.forEach(IrpcGeneratedKey::wipe)
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
        return persist(expected.copy(state = next))
    }

    internal fun quarantine(expected: RkpJournalRecord): RkpJournalRecord {
        requireCurrent(expected)
        require(
            expected.state == RkpJournalState.RKP_KEY_GENERATING ||
                expected.state == RkpJournalState.APP_KEY_GENERATING
        )
        blobs.deleteAll()
        return persist(expected.copy(state = RkpJournalState.QUARANTINED))
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
        blobs.deleteAll()
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
                current.count == expected.count
        ) {
            "stale or wrong batch"
        }
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

class DurableIrpcKeyBatchGenerator(
    private val client: IrpcClient,
    private val journal: RkpJournal,
) {
    fun generate(
        count: RkpKeyCount,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<IrpcKeyBatch> {
        val intent = journal.begin(count)
        val outcome = client.generateKeyBatch(count, deadline, cancellation)
        if (outcome is BrokerOutcome.Success) {
            journal.record(intent, outcome.value)
        } else {
            journal.quarantine(intent)
        }
        return outcome
    }
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
