package org.matrix.TEESimulator.rka.candidate

import java.nio.file.Path
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.rka.bridge.BridgeResult
import org.matrix.TEESimulator.rka.bridge.BrokerSidecarRole
import org.matrix.TEESimulator.rka.bridge.captureProductionPeerAuthorization

object CandidateRuntimeRegistry {
    private sealed interface State {
        data object PassThrough : State

        class Authorized(val runtime: CandidateRuntime) : State
    }

    @Volatile private var state: State = State.PassThrough

    fun initializeLifecycle() {
        state = State.PassThrough
        val captured = captureProductionPeerAuthorization(BrokerSidecarRole.CANDIDATE)
        if (captured !is BridgeResult.Success) return
        captured.value.use {
            val target = ConfigurationManager.configuredCandidateIdentity() ?: return
            val identityHash = IdentityHash.of(target.identityHash)
            val service =
                RemoteCandidateService(
                    identityHash,
                    BridgeRemoteCandidateBackend(),
                    FileRemoteCandidateStore(
                        Path.of("/data/adb/teesimulator-rka/state/candidate-keystore")
                    ),
                )
            state = State.Authorized(InstalledRuntime(target.uid, identityHash, service))
        }
    }

    fun current(): CandidateRuntime? = (state as? State.Authorized)?.runtime

    private class InstalledRuntime(
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
