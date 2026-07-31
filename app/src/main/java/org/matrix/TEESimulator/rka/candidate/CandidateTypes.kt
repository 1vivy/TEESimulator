package org.matrix.TEESimulator.rka.candidate

enum class CandidateError {
    INVALID_REQUEST,
    UNSUPPORTED_ALGORITHM,
    UNSUPPORTED_PURPOSE,
    UNSUPPORTED_DIGEST,
    UNSUPPORTED_EC_CURVE,
    POLICY_REJECTED,
    CAPACITY,
    STALE_HANDLE,
    TRANSPORT,
    OPERATION_LOST,
    QUARANTINED,
    CROSS_UID_GRANT_UNSUPPORTED,
}

sealed class CandidateResult<out T> {
    data class Success<T>(val value: T) : CandidateResult<T>()

    data class Failure(val error: CandidateError) : CandidateResult<Nothing>()
}

sealed class CandidateRoute<out T> {
    data object PassThrough : CandidateRoute<Nothing>()

    data class Remote<T>(val result: CandidateResult<T>) : CandidateRoute<T>()
}

abstract class FixedBytes(bytes: ByteArray, size: Int) {
    private val value = bytes.copyOf()

    init {
        require(value.size == size)
    }

    fun copyBytes(): ByteArray = value.copyOf()

    protected fun same(other: FixedBytes) = value.contentEquals(other.value)

    protected fun contentHash() = value.contentHashCode()

    override fun toString() = "<opaque:${value.size}>"
}

class IdentityHash private constructor(bytes: ByteArray) : FixedBytes(bytes, 32) {
    override fun equals(other: Any?) = other is IdentityHash && same(other)

    override fun hashCode() = contentHash()

    companion object {
        fun of(bytes: ByteArray) = IdentityHash(bytes)
    }
}

class RemoteKeyHandle private constructor(bytes: ByteArray) : FixedBytes(bytes, 16) {
    override fun equals(other: Any?) = other is RemoteKeyHandle && same(other)

    override fun hashCode() = contentHash()

    companion object {
        fun of(bytes: ByteArray) = RemoteKeyHandle(bytes)
    }
}

class RemoteOperationHandle private constructor(bytes: ByteArray) : FixedBytes(bytes, 16) {
    override fun equals(other: Any?) = other is RemoteOperationHandle && same(other)

    override fun hashCode() = contentHash()

    companion object {
        fun of(bytes: ByteArray) = RemoteOperationHandle(bytes)
    }
}

data class CandidateKeyId(val uid: Int, val namespace: Long, val alias: String) {
    init {
        require(uid >= 0)
        require(alias.toByteArray(Charsets.UTF_8).size in 1..255)
        require('\u0000' !in alias)
    }
}

enum class CandidateAlgorithm {
    EC,
    RSA,
}

enum class CandidateCurve {
    P256,
    P384,
}

enum class CandidatePurpose {
    SIGN,
    VERIFY,
}

enum class CandidateDigest {
    SHA256,
    NONE,
}

enum class CandidateSecurityLevel {
    TEE,
    STRONGBOX,
}

data class CandidateKeyShape(
    val algorithm: CandidateAlgorithm,
    val curve: CandidateCurve,
    val purpose: CandidatePurpose,
    val digest: CandidateDigest,
    val securityLevel: CandidateSecurityLevel,
    val challenge: ByteArray,
) {
    fun copiedChallenge() = challenge.copyOf()

    companion object {
        fun foreground(challenge: ByteArray) =
            CandidateKeyShape(
                CandidateAlgorithm.EC,
                CandidateCurve.P256,
                CandidatePurpose.SIGN,
                CandidateDigest.SHA256,
                CandidateSecurityLevel.TEE,
                challenge.copyOf(),
            )
    }
}

data class CandidateGenerateRequest(
    val id: CandidateKeyId,
    val identityHash: IdentityHash,
    val shape: CandidateKeyShape,
)

data class CandidateCharacteristics(
    val algorithm: CandidateAlgorithm,
    val curve: CandidateCurve,
    val purposes: Set<CandidatePurpose>,
    val digests: Set<CandidateDigest>,
    val securityLevel: CandidateSecurityLevel,
) {
    companion object {
        fun foreground() =
            CandidateCharacteristics(
                CandidateAlgorithm.EC,
                CandidateCurve.P256,
                setOf(CandidatePurpose.SIGN),
                setOf(CandidateDigest.SHA256),
                CandidateSecurityLevel.TEE,
            )
    }
}

enum class CandidateKeyState {
    ACTIVE,
    CONSUMED,
    DELETED,
}

enum class CandidateOperationState {
    OPEN,
    FINISHED,
    ABORTED,
    LOST,
}

data class CandidateOperationRecord(
    val handle: RemoteOperationHandle,
    val keyId: CandidateKeyId,
    val state: CandidateOperationState,
)

class CandidateKeyRecord(
    val id: CandidateKeyId,
    val identityHash: IdentityHash,
    val donorEpoch: Long,
    val profileEpoch: Long,
    val remoteHandle: RemoteKeyHandle,
    certificateChain: List<ByteArray>,
    val characteristics: CandidateCharacteristics,
    val state: CandidateKeyState,
) {
    private val chain = certificateChain.map(ByteArray::copyOf)

    init {
        require(chain.size in 2..20)
        require(chain.all { it.isNotEmpty() && it.size <= 65_536 })
        require(chain.sumOf(ByteArray::size) <= 524_288)
        require(donorEpoch >= 0 && profileEpoch >= 0)
    }

    fun certificateChain() = chain.map(ByteArray::copyOf)

    fun withState(next: CandidateKeyState) =
        CandidateKeyRecord(
            id,
            identityHash,
            donorEpoch,
            profileEpoch,
            remoteHandle,
            chain,
            characteristics,
            next,
        )
}

data class RemoteGenerateCommand(
    val aliasHandle: RemoteKeyHandle,
    val identityHash: IdentityHash,
    val challenge: ByteArray,
)

data class RemoteKeyMaterial(
    val handle: RemoteKeyHandle,
    val donorEpoch: Long,
    val profileEpoch: Long,
    val certificateChain: List<ByteArray>,
    val characteristics: CandidateCharacteristics,
)

interface RemoteCandidateBackend {
    fun generate(command: RemoteGenerateCommand): CandidateResult<RemoteKeyMaterial>

    fun get(handle: RemoteKeyHandle): CandidateResult<Unit>

    fun list(identityHash: IdentityHash): CandidateResult<List<RemoteKeyHandle>>

    fun delete(handle: RemoteKeyHandle): CandidateResult<Unit>

    fun begin(handle: RemoteKeyHandle): CandidateResult<RemoteOperationHandle>

    fun updateAad(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<Unit>

    fun update(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<Unit>

    fun finish(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<ByteArray>

    fun abort(handle: RemoteOperationHandle): CandidateResult<Unit>

    fun peerDied()
}

interface RemoteCandidateStore {
    fun all(): List<CandidateKeyRecord>

    fun find(id: CandidateKeyId): CandidateKeyRecord?

    fun replace(record: CandidateKeyRecord)

    fun operationStates(): List<CandidateOperationRecord>

    fun replaceOperation(record: CandidateOperationRecord)
}

class MemoryRemoteCandidateStore : RemoteCandidateStore {
    private val records = linkedMapOf<CandidateKeyId, CandidateKeyRecord>()
    private val operations = linkedMapOf<RemoteOperationHandle, CandidateOperationRecord>()

    @Synchronized override fun all() = records.values.toList()

    @Synchronized override fun find(id: CandidateKeyId) = records[id]

    @Synchronized
    override fun replace(record: CandidateKeyRecord) {
        records[record.id] = record
    }

    @Synchronized override fun operationStates() = operations.values.toList()

    @Synchronized
    override fun replaceOperation(record: CandidateOperationRecord) {
        operations[record.handle] = record
    }
}
