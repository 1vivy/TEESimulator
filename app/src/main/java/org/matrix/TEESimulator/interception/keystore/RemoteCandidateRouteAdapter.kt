package org.matrix.TEESimulator.interception.keystore

import org.matrix.TEESimulator.rka.candidate.CandidateGenerateRequest
import org.matrix.TEESimulator.rka.candidate.CandidateKeyId
import org.matrix.TEESimulator.rka.candidate.CandidateKeyRecord
import org.matrix.TEESimulator.rka.candidate.CandidateResult
import org.matrix.TEESimulator.rka.candidate.CandidateRoute
import org.matrix.TEESimulator.rka.candidate.IdentityHash
import org.matrix.TEESimulator.rka.candidate.RemoteCandidateService
import org.matrix.TEESimulator.rka.candidate.RemoteOperationHandle

interface LocalCandidateKeyMint {
    fun generate(request: CandidateGenerateRequest): CandidateResult<CandidateKeyRecord>

    fun get(uid: Int, id: CandidateKeyId): CandidateResult<CandidateKeyRecord>

    fun list(uid: Int, identityHash: IdentityHash): CandidateResult<List<CandidateKeyRecord>>

    fun delete(uid: Int, id: CandidateKeyId): CandidateResult<Unit>

    fun grant(uid: Int, id: CandidateKeyId, granteeUid: Int): CandidateResult<Unit>

    fun begin(uid: Int, id: CandidateKeyId): CandidateResult<RemoteOperationHandle>
}

class RemoteCandidateRouteAdapter(
    private val remote: RemoteCandidateService,
    private val local: LocalCandidateKeyMint,
) {
    fun generate(request: CandidateGenerateRequest) =
        route(remote.generate(request)) { local.generate(request) }

    fun get(uid: Int, id: CandidateKeyId) = route(remote.get(uid, id)) { local.get(uid, id) }

    fun list(uid: Int, identityHash: IdentityHash) =
        route(remote.list(uid, identityHash)) { local.list(uid, identityHash) }

    fun delete(uid: Int, id: CandidateKeyId) =
        route(remote.delete(uid, id)) { local.delete(uid, id) }

    fun grant(uid: Int, id: CandidateKeyId, granteeUid: Int) =
        route(remote.grant(uid, id, granteeUid)) { local.grant(uid, id, granteeUid) }

    fun begin(uid: Int, id: CandidateKeyId) = route(remote.begin(uid, id)) { local.begin(uid, id) }

    fun updateAad(handle: RemoteOperationHandle, input: ByteArray) = remote.updateAad(handle, input)

    fun update(handle: RemoteOperationHandle, input: ByteArray) = remote.update(handle, input)

    fun finish(handle: RemoteOperationHandle, input: ByteArray) = remote.finish(handle, input)

    fun abort(handle: RemoteOperationHandle) = remote.abort(handle)

    fun peerDied() = remote.peerDied()

    private fun <T> route(
        decision: CandidateRoute<T>,
        passThrough: () -> CandidateResult<T>,
    ): CandidateResult<T> =
        when (decision) {
            CandidateRoute.PassThrough -> passThrough()
            is CandidateRoute.Remote -> decision.result
        }
}
