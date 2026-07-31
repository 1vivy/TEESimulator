package org.matrix.TEESimulator.interception.keystore

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.matrix.TEESimulator.rka.candidate.CandidateCharacteristics
import org.matrix.TEESimulator.rka.candidate.CandidateGenerateRequest
import org.matrix.TEESimulator.rka.candidate.CandidateKeyId
import org.matrix.TEESimulator.rka.candidate.CandidateKeyRecord
import org.matrix.TEESimulator.rka.candidate.CandidateKeyShape
import org.matrix.TEESimulator.rka.candidate.CandidateResult
import org.matrix.TEESimulator.rka.candidate.CandidateRoute
import org.matrix.TEESimulator.rka.candidate.CandidateRuntime
import org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry
import org.matrix.TEESimulator.rka.candidate.IdentityHash
import org.matrix.TEESimulator.rka.candidate.MemoryRemoteCandidateStore
import org.matrix.TEESimulator.rka.candidate.RemoteCandidateBackend
import org.matrix.TEESimulator.rka.candidate.RemoteCandidateService
import org.matrix.TEESimulator.rka.candidate.RemoteGenerateCommand
import org.matrix.TEESimulator.rka.candidate.RemoteKeyHandle
import org.matrix.TEESimulator.rka.candidate.RemoteKeyMaterial
import org.matrix.TEESimulator.rka.candidate.RemoteOperationHandle

class RemoteCandidateProductionIntegrationTest {
    @After
    fun resetRegistry() {
        CandidateRuntimeRegistry.initializeLifecycle()
    }

    @Test
    fun registryPassesThroughWithoutCandidateAuthorization() {
        CandidateRuntimeRegistry.initializeLifecycle()

        assertNull(CandidateRuntimeRegistry.current())
    }

    @Test
    fun operationBinderRoutesCompleteSequenceToRemoteRuntime() {
        val fixture = ProductionFixture()
        val key =
            fixture.service
                .generate(CandidateGenerateRequest(fixture.id, fixture.identity, fixture.shape))
                .remoteSuccess()
        val handle = fixture.service.begin(fixture.uid, key.id).remoteSuccess()
        val binder = RemoteCandidateOperationBinder(fixture.runtime, handle)

        binder.updateAad(byteArrayOf(1))
        assertArrayEquals(ByteArray(0), binder.update(byteArrayOf(2)))
        assertArrayEquals(byteArrayOf(8, 9), binder.finish(byteArrayOf(3), null))

        assertEquals(
            listOf("generate", "begin", "updateAad", "update", "finish"),
            fixture.backend.calls,
        )
    }
}

internal class ProductionFixture {
    val uid = 10123
    val identity = IdentityHash.of(ByteArray(32) { 3 })
    val id = CandidateKeyId(uid, uid.toLong(), "foreground")
    val shape = CandidateKeyShape.foreground(byteArrayOf(1, 2, 3))
    val backend = ProductionBackend()
    val service =
        RemoteCandidateService(identity, backend, MemoryRemoteCandidateStore()) {
            RemoteKeyHandle.of(ByteArray(16) { 5 })
        }
    val runtime: CandidateRuntime = ProductionRuntime(uid, identity, service)
}

private class ProductionRuntime(
    private val admittedUid: Int,
    private val identity: IdentityHash,
    private val service: RemoteCandidateService,
) : CandidateRuntime {
    override fun admits(uid: Int) = uid == admittedUid

    override fun resolve(uid: Int, namespace: Long) = service.resolve(uid, namespace)

    override fun generate(id: CandidateKeyId, shape: CandidateKeyShape) =
        service.generate(CandidateGenerateRequest(id, identity, shape))

    override fun get(uid: Int, id: CandidateKeyId): CandidateRoute<CandidateKeyRecord> =
        service.get(uid, id)

    override fun list(uid: Int) = service.list(uid, identity)

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

internal class ProductionBackend : RemoteCandidateBackend {
    val calls = mutableListOf<String>()
    var failureStage: String? = null
    private val keyHandle = RemoteKeyHandle.of(ByteArray(16) { 5 })
    private val operationHandle = RemoteOperationHandle.of(ByteArray(16) { 6 })

    override fun generate(command: RemoteGenerateCommand) =
        success(
            "generate",
            RemoteKeyMaterial(
                keyHandle,
                1,
                2,
                listOf(byteArrayOf(1), byteArrayOf(2)),
                CandidateCharacteristics.foreground(),
            ),
        )

    override fun get(handle: RemoteKeyHandle) = success("get", Unit)

    override fun list(identityHash: IdentityHash) = success("list", listOf(keyHandle))

    override fun delete(handle: RemoteKeyHandle) = success("delete", Unit)

    override fun begin(handle: RemoteKeyHandle) = success("begin", operationHandle)

    override fun updateAad(handle: RemoteOperationHandle, input: ByteArray) =
        success("updateAad", Unit)

    override fun update(handle: RemoteOperationHandle, input: ByteArray) = success("update", Unit)

    override fun finish(handle: RemoteOperationHandle, input: ByteArray) =
        success("finish", byteArrayOf(8, 9))

    override fun abort(handle: RemoteOperationHandle) = success("abort", Unit)

    override fun peerDied() {
        calls += "peerDied"
    }

    private fun <T> success(stage: String, value: T): CandidateResult<T> {
        calls += stage
        return if (failureStage == stage) {
            CandidateResult.Failure(org.matrix.TEESimulator.rka.candidate.CandidateError.TRANSPORT)
        } else {
            CandidateResult.Success(value)
        }
    }
}

internal fun <T> org.matrix.TEESimulator.rka.candidate.CandidateRoute<T>.remoteSuccess(): T =
    ((this as org.matrix.TEESimulator.rka.candidate.CandidateRoute.Remote).result
            as CandidateResult.Success)
        .value
