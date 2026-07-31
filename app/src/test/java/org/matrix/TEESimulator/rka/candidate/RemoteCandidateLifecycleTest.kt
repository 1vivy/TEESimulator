package org.matrix.TEESimulator.rka.candidate

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.interception.keystore.LocalCandidateKeyMint
import org.matrix.TEESimulator.interception.keystore.RemoteCandidateRouteAdapter

class RemoteCandidateLifecycleTest {
    @Test
    fun generateBeginUpdateAadFinishDelete() {
        val fixture = CandidateFixture()
        val generated = fixture.adapter.generate(fixture.request)
        val key = generated.success()
        val operation = fixture.adapter.begin(fixture.uid, key.id).success()

        fixture.adapter.updateAad(operation, byteArrayOf(1)).success()
        fixture.adapter.update(operation, byteArrayOf(2, 3)).success()
        assertTrue(fixture.adapter.finish(operation, byteArrayOf(4)).success().isNotEmpty())
        fixture.adapter.delete(fixture.uid, key.id).success()

        assertEquals(CandidateKeyState.DELETED, fixture.store.find(key.id)?.state)
        assertEquals(0, fixture.local.calls)
    }

    @Test
    fun persistenceRestartListGetAndLostReconciliation() {
        val fixture = CandidateFixture()
        val key = fixture.adapter.generate(fixture.request).success()
        val reopenedStore = FileRemoteCandidateStore(fixture.storePath)
        val restarted =
            RemoteCandidateRouteAdapter(
                RemoteCandidateService(fixture.identity, fixture.backend, reopenedStore),
                fixture.local,
            )

        assertEquals(key.id, restarted.get(fixture.uid, key.id).success().id)
        assertEquals(
            listOf(key.id),
            restarted.list(fixture.uid, fixture.identity).success().map { it.id },
        )
        val operation = restarted.begin(fixture.uid, key.id).success()
        restarted.peerDied()

        assertEquals(
            CandidateError.OPERATION_LOST,
            restarted.update(operation, byteArrayOf(9)).failure(),
        )
        assertEquals(0, fixture.local.calls)
    }

    @Test
    fun abortDoesNotConsumeKeyAndGrantIsUnsupported() {
        val fixture = CandidateFixture()
        val key = fixture.adapter.generate(fixture.request).success()
        val first = fixture.adapter.begin(fixture.uid, key.id).success()
        fixture.adapter.abort(first).success()
        fixture.adapter.begin(fixture.uid, key.id).success()

        assertEquals(
            CandidateError.CROSS_UID_GRANT_UNSUPPORTED,
            fixture.adapter.grant(fixture.uid, key.id, fixture.uid + 1).failure(),
        )
        assertEquals(0, fixture.local.calls)
    }
}

class FailClosedRouteTest {
    @Test
    fun remoteFailureNeverFallsBack() {
        val fixture = CandidateFixture(failGenerate = CandidateError.TRANSPORT)

        assertEquals(CandidateError.TRANSPORT, fixture.adapter.generate(fixture.request).failure())
        assertEquals(0, fixture.local.calls)
        assertTrue(fixture.store.all().isEmpty())
    }

    @Test
    fun nonTargetPassesThroughButExactRemoteShapesFailClosed() {
        val fixture = CandidateFixture()
        fixture.adapter.generate(
            fixture.request.copy(identityHash = IdentityHash.of(ByteArray(32) { 7 }))
        )
        assertEquals(1, fixture.local.calls)

        val bad =
            fixture.request.copy(shape = fixture.request.shape.copy(digest = CandidateDigest.NONE))
        assertEquals(CandidateError.UNSUPPORTED_DIGEST, fixture.adapter.generate(bad).failure())
        assertEquals(1, fixture.local.calls)
    }
}

private class CandidateFixture(failGenerate: CandidateError? = null) {
    val uid = 10123
    val identity = IdentityHash.of(ByteArray(32) { 3 })
    val storePath = Files.createTempDirectory("remote-candidate-store-")
    val store = FileRemoteCandidateStore(storePath)
    val backend = FakeRemoteCandidateBackend(failGenerate)
    val local = CountingLocalKeyMint()
    val adapter =
        RemoteCandidateRouteAdapter(
            RemoteCandidateService(identity, backend, store) {
                RemoteKeyHandle.of(ByteArray(16) { 5 })
            },
            local,
        )
    val request =
        CandidateGenerateRequest(
            CandidateKeyId(uid, uid.toLong(), "foreground"),
            identity,
            CandidateKeyShape.foreground(byteArrayOf(1, 2, 3)),
        )
}

private class CountingLocalKeyMint : LocalCandidateKeyMint {
    var calls = 0

    override fun generate(request: CandidateGenerateRequest): CandidateResult<CandidateKeyRecord> {
        calls += 1
        return CandidateResult.Failure(CandidateError.INVALID_REQUEST)
    }

    override fun get(uid: Int, id: CandidateKeyId) = generateFailure<CandidateKeyRecord>()

    override fun list(uid: Int, identityHash: IdentityHash) =
        generateFailure<List<CandidateKeyRecord>>()

    override fun delete(uid: Int, id: CandidateKeyId) = generateFailure<Unit>()

    override fun grant(uid: Int, id: CandidateKeyId, granteeUid: Int) = generateFailure<Unit>()

    override fun begin(uid: Int, id: CandidateKeyId) = generateFailure<RemoteOperationHandle>()

    private fun <T> generateFailure(): CandidateResult<T> {
        calls += 1
        return CandidateResult.Failure(CandidateError.INVALID_REQUEST)
    }
}

private class FakeRemoteCandidateBackend(private val failGenerate: CandidateError?) :
    RemoteCandidateBackend {
    private val handle = RemoteKeyHandle.of(ByteArray(16) { 5 })
    private var operationId = 5

    override fun generate(command: RemoteGenerateCommand) =
        failGenerate?.let { CandidateResult.Failure(it) }
            ?: CandidateResult.Success(
                RemoteKeyMaterial(
                    handle,
                    11,
                    12,
                    listOf(byteArrayOf(0x30, 1), byteArrayOf(0x30, 2)),
                    CandidateCharacteristics.foreground(),
                )
            )

    override fun get(handle: RemoteKeyHandle) = CandidateResult.Success(Unit)

    override fun list(identityHash: IdentityHash) = CandidateResult.Success(listOf(handle))

    override fun delete(handle: RemoteKeyHandle) = CandidateResult.Success(Unit)

    override fun begin(handle: RemoteKeyHandle) =
        CandidateResult.Success(
            RemoteOperationHandle.of(ByteArray(16) { (++operationId).toByte() })
        )

    override fun updateAad(handle: RemoteOperationHandle, input: ByteArray) =
        CandidateResult.Success(Unit)

    override fun update(handle: RemoteOperationHandle, input: ByteArray) =
        CandidateResult.Success(Unit)

    override fun finish(handle: RemoteOperationHandle, input: ByteArray) =
        CandidateResult.Success(byteArrayOf(8, 9))

    override fun abort(handle: RemoteOperationHandle) = CandidateResult.Success(Unit)

    override fun peerDied() = Unit
}

private fun <T> CandidateResult<T>.success(): T = (this as CandidateResult.Success<T>).value

private fun CandidateResult<*>.failure(): CandidateError = (this as CandidateResult.Failure).error
