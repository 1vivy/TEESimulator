package org.matrix.teesimulator.twophone

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class KeyState {
    ABSENT,
    CREATING,
    ACTIVE,
    SUPERSEDED,
    DELETE_PENDING,
    DELETED,
    QUARANTINED,
}

enum class OperationState {
    BEGUN,
    AAD,
    DATA,
    FINISHING,
    FINISHED,
    ABORTED,
    LOST,
}

data class KeyHandle(val id: UUID, val binding: ByteArray)

data class GenerateRequest(
    internal val logicalName: String,
    val challenge: ByteArray,
    val caller: CallerIdentity,
) {
    fun body() =
        CanonicalBody.of(
            "logical-name-hash" to logicalName.encodeToByteArray().sha256(),
            "challenge" to challenge,
            "caller" to caller.stableCanonical(),
        )
}

data class GeneratedKey(
    val handle: KeyHandle,
    val attestationChallenge: ByteArray,
    val publicKey: ByteArray,
    val certificateChain: List<ByteArray>,
)

data class KeyMetadata(val state: KeyState, val publicKey: ByteArray)

data class OperationHandle(val id: UUID, val keyId: UUID, val binding: ByteArray)

sealed class DonorException(message: String) : RuntimeException(message) {
    class WrongCaller : DonorException("wrong caller")

    class WrongPair : DonorException("wrong pinned pair")

    class CopiedHandle : DonorException("invalid or copied handle")

    class InvalidState : DonorException("invalid state transition")

    class ImportNotSafelyModeled :
        DonorException("private-key import custody is not safely modeled")
}

class DonorCounters {
    val generateCounter = AtomicInteger()
    val deleteCounter = AtomicInteger()
    val beginCounter = AtomicInteger()
    val updateAadCounter = AtomicInteger()
    val updateCounter = AtomicInteger()
    val abortCounter = AtomicInteger()
    val strongBoxCounter = AtomicInteger()
    val avfCounter = AtomicInteger()
    val generate: Int
        get() = generateCounter.get()

    val delete: Int
        get() = deleteCounter.get()

    val begin: Int
        get() = beginCounter.get()

    val updateAad: Int
        get() = updateAadCounter.get()

    val update: Int
        get() = updateCounter.get()

    val abort: Int
        get() = abortCounter.get()

    val strongBox: Int
        get() = strongBoxCounter.get()

    val avf: Int
        get() = avfCounter.get()
}

class InMemoryDonorStore {
    internal val keys = ConcurrentHashMap<UUID, DonorKey>()
    internal val logicalActive = ConcurrentHashMap<String, UUID>()
    internal val operations = ConcurrentHashMap<UUID, DonorOperation>()
    internal val handleSecret = ByteArray(32).also(SecureRandom()::nextBytes)
}

internal data class DonorKey(
    val id: UUID,
    val logicalName: String,
    val caller: CallerIdentity,
    val pair: PairIdentity,
    val secret: ByteArray,
    val publicKey: ByteArray,
    @Volatile var state: KeyState,
)

internal data class DonorOperation(
    val id: UUID,
    val keyId: UUID,
    val caller: CallerIdentity,
    val pair: PairIdentity,
    @Volatile var state: OperationState,
    val transcript: MutableList<ByteArray> = mutableListOf(),
)

class FakeDonorAdapter
private constructor(
    private val pair: PairIdentity,
    private val clock: MutableClock,
    private val store: InMemoryDonorStore,
    val counters: DonorCounters,
    private val presentedPair: PairIdentity,
    recoverOperationsAfterRestart: Boolean,
) {
    constructor(
        pair: PairIdentity,
        clock: MutableClock,
        store: InMemoryDonorStore = InMemoryDonorStore(),
        counters: DonorCounters = DonorCounters(),
    ) : this(pair, clock, store, counters, pair, true)

    init {
        if (recoverOperationsAfterRestart) recoverOperationsAfterRestart()
    }

    fun generate(request: GenerateRequest): GeneratedKey {
        verifyPair()
        require(request.challenge.isNotEmpty() && request.challenge.size <= 128)
        return synchronized(store) {
            store.logicalActive[request.logicalName]?.let { oldId ->
                store.keys[oldId]?.let {
                    if (it.state == KeyState.ACTIVE) it.state = KeyState.SUPERSEDED
                }
            }
            val id = UUID.randomUUID()
            val secret = ByteArray(32).also(SecureRandom()::nextBytes)
            val publicKey = canonicalBytes(id.bytes(), secret).sha256()
            val key =
                DonorKey(
                    id,
                    request.logicalName,
                    request.caller,
                    pair,
                    secret,
                    publicKey,
                    KeyState.CREATING,
                )
            store.keys[id] = key
            key.state = KeyState.ACTIVE
            store.logicalActive[request.logicalName] = id
            counters.generateCounter.incrementAndGet()
            GeneratedKey(
                handleFor(key),
                request.challenge.copyOf(),
                publicKey.copyOf(),
                listOf(
                    canonicalBytes(publicKey, request.challenge, request.caller.stableCanonical())
                        .sha256()
                ),
            )
        }
    }

    fun importKey(privateMaterial: ByteArray, caller: CallerIdentity): Nothing {
        throw DonorException.ImportNotSafelyModeled()
    }

    fun metadata(handle: KeyHandle, caller: CallerIdentity): KeyMetadata {
        val key = key(handle, caller)
        return KeyMetadata(key.state, key.publicKey.copyOf())
    }

    fun delete(handle: KeyHandle, caller: CallerIdentity) {
        synchronized(store) {
            val key = key(handle, caller)
            if (key.state == KeyState.DELETED) return
            if (key.state == KeyState.QUARANTINED) throw DonorException.InvalidState()
            key.state = KeyState.DELETE_PENDING
            store.operations.values
                .filter { it.keyId == key.id }
                .forEach { operation ->
                    synchronized(operation) {
                        if (!operation.state.isTerminal()) {
                            operation.state = OperationState.ABORTED
                        }
                    }
                }
            key.secret.fill(0)
            key.state = KeyState.DELETED
            store.logicalActive.remove(key.logicalName, key.id)
            counters.deleteCounter.incrementAndGet()
        }
    }

    fun begin(handle: KeyHandle, caller: CallerIdentity): OperationHandle =
        synchronized(store) {
            val key = key(handle, caller)
            if (key.state != KeyState.ACTIVE && key.state != KeyState.SUPERSEDED) {
                throw DonorException.InvalidState()
            }
            val id = UUID.randomUUID()
            val operation = DonorOperation(id, key.id, caller, key.pair, OperationState.BEGUN)
            store.operations[id] = operation
            counters.beginCounter.incrementAndGet()
            operationHandle(operation)
        }

    fun updateAad(handle: OperationHandle, caller: CallerIdentity, input: ByteArray) {
        val operation = operation(handle, caller)
        synchronized(operation) {
            if (operation.state !in setOf(OperationState.BEGUN, OperationState.AAD)) {
                throw DonorException.InvalidState()
            }
            operation.transcript += input.copyOf()
            operation.state = OperationState.AAD
            counters.updateAadCounter.incrementAndGet()
        }
    }

    fun update(handle: OperationHandle, caller: CallerIdentity, input: ByteArray): ByteArray {
        val operation = operation(handle, caller)
        synchronized(operation) {
            if (
                operation.state !in
                    setOf(OperationState.BEGUN, OperationState.AAD, OperationState.DATA)
            ) {
                throw DonorException.InvalidState()
            }
            operation.transcript += input.copyOf()
            operation.state = OperationState.DATA
            counters.updateCounter.incrementAndGet()
            return ByteArray(0)
        }
    }

    fun finish(handle: OperationHandle, caller: CallerIdentity, input: ByteArray): ByteArray {
        val operation = operation(handle, caller)
        synchronized(operation) {
            if (
                operation.state in
                    setOf(OperationState.FINISHED, OperationState.ABORTED, OperationState.LOST)
            ) {
                throw DonorException.InvalidState()
            }
            operation.state = OperationState.FINISHING
            val result =
                sign(
                    store.keys.getValue(operation.keyId).secret,
                    canonicalBytes(*(operation.transcript + input).toTypedArray()),
                )
            operation.state = OperationState.FINISHED
            return result
        }
    }

    fun abort(handle: OperationHandle, caller: CallerIdentity) {
        val operation = operation(handle, caller)
        synchronized(operation) {
            if (operation.state == OperationState.FINISHED) throw DonorException.InvalidState()
            operation.state = OperationState.ABORTED
            counters.abortCounter.incrementAndGet()
        }
    }

    fun operationState(handle: OperationHandle): OperationState =
        store.operations[handle.id]?.state ?: OperationState.LOST

    fun operationStates(): Map<UUID, OperationState> = store.operations.mapValues { it.value.state }

    fun allMetadata(): Map<KeyHandle, KeyState> =
        store.keys.values.associate { handleFor(it) to it.state }

    fun debugTargetState(): List<String> =
        store.keys.values.map { "${it.id}:${it.state}:${it.publicKey.toHex()}" }

    fun forPresentedPair(other: PairIdentity) =
        FakeDonorAdapter(pair, clock, store, counters, other, false)

    fun dispatch(method: Method, body: CanonicalBody, caller: CallerIdentity): ByteArray =
        when (method) {
            Method.GENERATE -> {
                counters.generateCounter.incrementAndGet()
                canonicalBytes(body.sha256, caller.stableCanonical())
            }
            else -> canonicalBytes(method.name.encodeToByteArray(), body.sha256)
        }

    private fun key(handle: KeyHandle, caller: CallerIdentity): DonorKey {
        verifyPair()
        val key = store.keys[handle.id] ?: throw DonorException.CopiedHandle()
        if (!key.caller.matchesStableIdentity(caller)) throw DonorException.WrongCaller()
        if (!MessageDigest.isEqual(handle.binding, handleBinding(key))) {
            throw DonorException.CopiedHandle()
        }
        return key
    }

    private fun operation(handle: OperationHandle, caller: CallerIdentity): DonorOperation {
        verifyPair()
        val operation = store.operations[handle.id] ?: throw DonorException.CopiedHandle()
        if (operation.pair != pair) throw DonorException.WrongPair()
        if (!operation.caller.matchesStableIdentity(caller)) throw DonorException.WrongCaller()
        if (handle.keyId != operation.keyId) throw DonorException.CopiedHandle()
        val expected = operationBinding(operation)
        if (!MessageDigest.isEqual(handle.binding, expected)) throw DonorException.CopiedHandle()
        return operation
    }

    private fun verifyPair() {
        if (presentedPair != pair) throw DonorException.WrongPair()
    }

    private fun recoverOperationsAfterRestart() {
        synchronized(store) {
            store.operations.values
                .filter { it.pair == pair }
                .forEach { operation ->
                    synchronized(operation) {
                        if (!operation.state.isTerminal()) {
                            operation.state = OperationState.LOST
                        }
                    }
                }
        }
    }

    private fun handleFor(key: DonorKey) = KeyHandle(key.id, handleBinding(key))

    private fun handleBinding(key: DonorKey) =
        sign(
            store.handleSecret,
            canonicalBytes(key.id.bytes(), key.caller.stableCanonical(), pair.canonical()),
        )

    private fun operationHandle(operation: DonorOperation) =
        OperationHandle(operation.id, operation.keyId, operationBinding(operation))

    private fun operationBinding(operation: DonorOperation) =
        sign(
            store.handleSecret,
            canonicalBytes(
                operation.id.bytes(),
                operation.keyId.bytes(),
                operation.caller.stableCanonical(),
                operation.pair.canonical(),
            ),
        )
}

private fun sign(secret: ByteArray, value: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(secret, "HmacSHA256"))
        doFinal(value)
    }

private fun UUID.bytes(): ByteArray =
    ByteBuffer.allocate(16).putLong(mostSignificantBits).putLong(leastSignificantBits).array()

private fun CallerIdentity.matchesStableIdentity(other: CallerIdentity): Boolean =
    signingCertificateDigest == other.signingCertificateDigest &&
        attestationApplicationIdDigest == other.attestationApplicationIdDigest

private fun OperationState.isTerminal(): Boolean =
    this == OperationState.FINISHED || this == OperationState.ABORTED || this == OperationState.LOST

private fun PairIdentity.canonical(): ByteArray =
    canonicalBytes(targetPin.encodeToByteArray(), donorPin.encodeToByteArray())
