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
            "caller" to caller.canonical(),
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
    val beginCounter = AtomicInteger()
    val updateCounter = AtomicInteger()
    val strongBoxCounter = AtomicInteger()
    val avfCounter = AtomicInteger()
    val generate: Int
        get() = generateCounter.get()

    val begin: Int
        get() = beginCounter.get()

    val update: Int
        get() = updateCounter.get()

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
    @Volatile var state: OperationState,
    val transcript: MutableList<ByteArray> = mutableListOf(),
    var lastUpdateInput: ByteArray? = null,
    var lastUpdateOutput: ByteArray? = null,
)

class FakeDonorAdapter(
    private val pair: PairIdentity,
    private val clock: MutableClock,
    private val store: InMemoryDonorStore = InMemoryDonorStore(),
    val counters: DonorCounters = DonorCounters(),
    private val presentedPair: PairIdentity = pair,
) {
    init {
        store.operations.values
            .filter { it.state !in setOf(OperationState.FINISHED, OperationState.ABORTED) }
            .forEach { it.state = OperationState.LOST }
    }

    @Synchronized
    fun generate(request: GenerateRequest): GeneratedKey {
        verifyPair()
        require(request.challenge.isNotEmpty() && request.challenge.size <= 128)
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
        return GeneratedKey(
            handleFor(key),
            request.challenge.copyOf(),
            publicKey.copyOf(),
            listOf(
                canonicalBytes(publicKey, request.challenge, request.caller.canonical()).sha256()
            ),
        )
    }

    fun importKey(privateMaterial: ByteArray, caller: CallerIdentity): Nothing {
        throw DonorException.ImportNotSafelyModeled()
    }

    fun metadata(handle: KeyHandle, caller: CallerIdentity): KeyMetadata {
        val key = key(handle, caller)
        return KeyMetadata(key.state, key.publicKey.copyOf())
    }

    @Synchronized
    fun delete(handle: KeyHandle, caller: CallerIdentity) {
        val key = key(handle, caller)
        if (key.state == KeyState.DELETED) return
        if (key.state == KeyState.QUARANTINED) throw DonorException.InvalidState()
        key.state = KeyState.DELETE_PENDING
        key.secret.fill(0)
        key.state = KeyState.DELETED
        store.logicalActive.remove(key.logicalName, key.id)
    }

    fun begin(handle: KeyHandle, caller: CallerIdentity): OperationHandle {
        val key = key(handle, caller)
        if (key.state != KeyState.ACTIVE && key.state != KeyState.SUPERSEDED) {
            throw DonorException.InvalidState()
        }
        val id = UUID.randomUUID()
        val operation = DonorOperation(id, key.id, caller, OperationState.BEGUN)
        store.operations[id] = operation
        counters.beginCounter.incrementAndGet()
        return operationHandle(operation)
    }

    fun updateAad(handle: OperationHandle, caller: CallerIdentity, input: ByteArray) {
        val operation = operation(handle, caller)
        synchronized(operation) {
            if (operation.state !in setOf(OperationState.BEGUN, OperationState.AAD)) {
                throw DonorException.InvalidState()
            }
            operation.transcript += input.copyOf()
            operation.state = OperationState.AAD
        }
    }

    fun update(handle: OperationHandle, caller: CallerIdentity, input: ByteArray): ByteArray {
        val operation = operation(handle, caller)
        synchronized(operation) {
            if (
                operation.lastUpdateInput?.let { MessageDigest.isEqual(it, input) } == true &&
                    operation.lastUpdateOutput != null
            ) {
                return operation.lastUpdateOutput!!.copyOf()
            }
            if (
                operation.state !in
                    setOf(OperationState.BEGUN, OperationState.AAD, OperationState.DATA)
            ) {
                throw DonorException.InvalidState()
            }
            val output = sign(store.keys.getValue(operation.keyId).secret, input)
            operation.transcript += input.copyOf()
            operation.lastUpdateInput = input.copyOf()
            operation.lastUpdateOutput = output.copyOf()
            operation.state = OperationState.DATA
            counters.updateCounter.incrementAndGet()
            return output
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
        FakeDonorAdapter(pair, clock, store, counters, other)

    fun dispatch(method: Method, body: CanonicalBody, caller: CallerIdentity): ByteArray =
        when (method) {
            Method.GENERATE -> {
                counters.generateCounter.incrementAndGet()
                canonicalBytes(body.sha256, caller.canonical())
            }
            else -> canonicalBytes(method.name.encodeToByteArray(), body.sha256)
        }

    private fun key(handle: KeyHandle, caller: CallerIdentity): DonorKey {
        verifyPair()
        val key = store.keys[handle.id] ?: throw DonorException.CopiedHandle()
        if (key.caller != caller) throw DonorException.WrongCaller()
        if (!MessageDigest.isEqual(handle.binding, handleBinding(key))) {
            throw DonorException.CopiedHandle()
        }
        return key
    }

    private fun operation(handle: OperationHandle, caller: CallerIdentity): DonorOperation {
        verifyPair()
        val operation = store.operations[handle.id] ?: throw DonorException.CopiedHandle()
        if (operation.caller != caller) throw DonorException.WrongCaller()
        val expected = operationBinding(operation)
        if (!MessageDigest.isEqual(handle.binding, expected)) throw DonorException.CopiedHandle()
        return operation
    }

    private fun verifyPair() {
        if (presentedPair != pair) throw DonorException.WrongPair()
    }

    private fun handleFor(key: DonorKey) = KeyHandle(key.id, handleBinding(key))

    private fun handleBinding(key: DonorKey) =
        sign(
            store.handleSecret,
            canonicalBytes(key.id.bytes(), key.caller.canonical(), pair.canonical()),
        )

    private fun operationHandle(operation: DonorOperation) =
        OperationHandle(operation.id, operation.keyId, operationBinding(operation))

    private fun operationBinding(operation: DonorOperation) =
        sign(
            store.handleSecret,
            canonicalBytes(
                operation.id.bytes(),
                operation.keyId.bytes(),
                operation.caller.canonical(),
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

private fun CallerIdentity.canonical(): ByteArray =
    canonicalBytes(
        ByteBuffer.allocate(4).putInt(uid).array(),
        signingCertificateDigest.encodeToByteArray(),
        attestationApplicationIdDigest.encodeToByteArray(),
    )

private fun PairIdentity.canonical(): ByteArray =
    canonicalBytes(targetPin.encodeToByteArray(), donorPin.encodeToByteArray())
