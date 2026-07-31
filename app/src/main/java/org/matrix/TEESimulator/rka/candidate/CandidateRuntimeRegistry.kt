package org.matrix.TEESimulator.rka.candidate

object CandidateRuntimeRegistry {
    sealed interface State {
        data object PassThrough : State

        class Authorized internal constructor(val runtime: CandidateRuntime) : State
    }

    @Volatile private var state: State = State.PassThrough

    fun initializeLifecycle() {
        state = State.PassThrough
    }

    fun current(): CandidateRuntime? = (state as? State.Authorized)?.runtime

    internal fun installFromValidatedBridge(runtime: CandidateRuntime) {
        state = State.Authorized(runtime)
    }
}

interface CandidateRuntime {
    fun admits(uid: Int): Boolean

    fun resolve(uid: Int, namespace: Long): CandidateKeyId?

    fun generate(id: CandidateKeyId, shape: CandidateKeyShape): CandidateRoute<CandidateKeyRecord>

    fun get(uid: Int, id: CandidateKeyId): CandidateRoute<CandidateKeyRecord>

    fun list(uid: Int): CandidateRoute<List<CandidateKeyRecord>>

    fun delete(uid: Int, id: CandidateKeyId): CandidateRoute<Unit>

    fun grant(uid: Int, id: CandidateKeyId, granteeUid: Int): CandidateRoute<Unit>

    fun begin(uid: Int, id: CandidateKeyId): CandidateRoute<RemoteOperationHandle>

    fun updateAad(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<Unit>

    fun update(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<Unit>

    fun finish(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<ByteArray>

    fun abort(handle: RemoteOperationHandle): CandidateResult<Unit>

    fun peerDied()
}

class ServiceCandidateRuntime(
    private val admittedUid: Int,
    private val identityHash: IdentityHash,
    private val service: RemoteCandidateService,
) : CandidateRuntime {
    override fun admits(uid: Int) = uid == admittedUid

    override fun resolve(uid: Int, namespace: Long) =
        if (admits(uid)) service.resolve(uid, namespace) else null

    override fun generate(id: CandidateKeyId, shape: CandidateKeyShape) =
        if (admits(id.uid)) service.generate(CandidateGenerateRequest(id, identityHash, shape))
        else CandidateRoute.PassThrough

    override fun get(uid: Int, id: CandidateKeyId) = service.get(uid, id)

    override fun list(uid: Int) =
        if (admits(uid)) service.list(uid, identityHash) else CandidateRoute.PassThrough

    override fun delete(uid: Int, id: CandidateKeyId) = service.delete(uid, id)

    override fun grant(uid: Int, id: CandidateKeyId, granteeUid: Int) =
        service.grant(uid, id, granteeUid)

    override fun begin(uid: Int, id: CandidateKeyId) = service.begin(uid, id)

    override fun updateAad(handle: RemoteOperationHandle, input: ByteArray) =
        service.updateAad(handle, input)

    override fun update(handle: RemoteOperationHandle, input: ByteArray) =
        service.update(handle, input)

    override fun finish(handle: RemoteOperationHandle, input: ByteArray) =
        service.finish(handle, input)

    override fun abort(handle: RemoteOperationHandle) = service.abort(handle)

    override fun peerDied() = service.peerDied()
}
