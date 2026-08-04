package org.matrix.TEESimulator.rka.candidate

import java.lang.reflect.Proxy
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.LocalCandidateKeyMint
import org.matrix.TEESimulator.interception.keystore.RemoteCandidateRouteAdapter
import org.matrix.TEESimulator.rka.donor.DonorFixture
import org.matrix.TEESimulator.rka.identity.AuthoritativeIdentity
import org.matrix.TEESimulator.rka.identity.CandidateIdentityAuthority
import org.matrix.TEESimulator.rka.identity.RawPackageIdentity

class RemoteCandidateLifecycleTest {
    @Test
    fun twoConfiguredCandidateUidsBothProduceAdmittedRuntimes() {
        // Given
        val configured = linkedMapOf(10_123 to "candidate.first", 10_124 to "candidate.second")
        val authority = candidateAuthority(configured)
        val registryState = registryStateField().get(CandidateRuntimeRegistry)

        try {
            // When
            val identities =
                ConfigurationManager.configuredCandidateIdentities(
                    configured.keys.toList(),
                    authority,
                )
            val runtimes =
                identities.associate { identity ->
                    IdentityHash.of(identity.identityHash) to runtimeFor(identity.uid)
                }
            runCatching { registryStateField().set(CandidateRuntimeRegistry, runtimes) }
            val first = currentRuntime(10_123)
            val second = currentRuntime(10_124)

            // Then
            assertEquals(2, identities.size)
            assertNotNull(first)
            assertNotNull(second)
            assertNotSame(first, second)
        } finally {
            registryStateField().set(CandidateRuntimeRegistry, registryState)
        }
    }

    @Test
    fun getDeleteAndGrantRejectAnUnadmittedUid() {
        // Given
        val fixture = CandidateFixture()
        val key = fixture.adapter.generate(fixture.request).success()
        val runtime = installedRuntime(fixture.uid, fixture.identity, fixture.service)
        val foreignUid = fixture.uid + 1

        // When
        val fetched = runtime.get(foreignUid, key.id)
        val deleted = runtime.delete(foreignUid, key.id)
        val granted = runtime.grant(foreignUid, key.id, foreignUid + 1)

        // Then
        assertEquals(CandidateRoute.PassThrough, fetched)
        assertEquals(CandidateRoute.PassThrough, deleted)
        assertEquals(CandidateRoute.PassThrough, granted)
    }

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
        val afterLiveRestart =
            RemoteCandidateRouteAdapter(
                RemoteCandidateService(
                    fixture.identity,
                    fixture.backend,
                    FileRemoteCandidateStore(fixture.storePath),
                ),
                fixture.local,
            )

        assertEquals(
            CandidateError.OPERATION_LOST,
            afterLiveRestart.update(operation, byteArrayOf(9)).failure(),
        )
        assertEquals(0, fixture.local.calls)
    }

    @Test
    fun persistenceRoundTripsExactCharacteristics() {
        val fixture = CandidateFixture()
        val characteristics =
            CandidateCharacteristics(
                CandidateAlgorithm.RSA,
                CandidateCurve.P384,
                setOf(CandidatePurpose.SIGN, CandidatePurpose.VERIFY),
                setOf(CandidateDigest.SHA256, CandidateDigest.NONE),
                CandidateSecurityLevel.STRONGBOX,
            )
        val record =
            CandidateKeyRecord(
                fixture.request.id,
                fixture.identity,
                21,
                22,
                RemoteKeyHandle.of(ByteArray(16) { 4 }),
                listOf(byteArrayOf(1), byteArrayOf(2)),
                characteristics,
                CandidateKeyState.CONSUMED,
            )

        fixture.store.replace(record)
        val reopened = FileRemoteCandidateStore(fixture.storePath).find(record.id)!!

        assertEquals(characteristics, reopened.characteristics)
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

private fun candidateAuthority(candidates: Map<Int, String>): CandidateIdentityAuthority {
    val signer = DonorFixture().rootCertificate.encoded
    return object : CandidateIdentityAuthority {
        override fun snapshot(uid: Int, epoch: Long) =
            AuthoritativeIdentity(
                0,
                uid,
                listOf(
                    RawPackageIdentity(candidates.getValue(uid), 1u, listOf(signer), listOf(signer))
                ),
            )
    }
}

private fun runtimeFor(uid: Int): CandidateRuntime =
    Proxy.newProxyInstance(
        CandidateRuntime::class.java.classLoader,
        arrayOf(CandidateRuntime::class.java),
    ) { _, method, arguments ->
        if (method.name == "admits") arguments?.single() == uid
        else throw UnsupportedOperationException(method.name)
    } as CandidateRuntime

private fun currentRuntime(uid: Int): CandidateRuntime? =
    CandidateRuntimeRegistry::class
        .java
        .methods
        .singleOrNull { it.name == "current" && it.parameterCount == 1 }
        ?.invoke(CandidateRuntimeRegistry, uid) as? CandidateRuntime

private fun installedRuntime(
    uid: Int,
    identity: IdentityHash,
    service: RemoteCandidateService,
): CandidateRuntime {
    val type =
        CandidateRuntimeRegistry::class.java.declaredClasses.single {
            it.simpleName == "InstalledRuntime"
        }
    val constructor =
        type.getDeclaredConstructor(
            Int::class.javaPrimitiveType,
            IdentityHash::class.java,
            RemoteCandidateService::class.java,
        )
    constructor.isAccessible = true
    return constructor.newInstance(uid, identity, service) as CandidateRuntime
}

private fun registryStateField() =
    CandidateRuntimeRegistry::class.java.getDeclaredField("state").apply { isAccessible = true }

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

    @Test
    fun everyPostAdmissionStageAndErrorClassNeverFallsBack() {
        CandidateError.entries.forEach { error ->
            val fixture = CandidateFixture()
            fixture.backend.failure = "generate" to error
            assertEquals(error, fixture.adapter.generate(fixture.request).failure())
            assertEquals(0, fixture.local.calls)
        }

        listOf("get", "list", "delete", "begin").forEach { stage ->
            val fixture = CandidateFixture()
            val key = fixture.adapter.generate(fixture.request).success()
            fixture.backend.failure = stage to CandidateError.TRANSPORT
            val actual =
                when (stage) {
                    "get" -> fixture.adapter.get(fixture.uid, key.id)
                    "list" -> fixture.adapter.list(fixture.uid, fixture.identity)
                    "delete" -> fixture.adapter.delete(fixture.uid, key.id)
                    else -> fixture.adapter.begin(fixture.uid, key.id)
                }
            assertEquals(CandidateError.TRANSPORT, actual.failure())
            assertEquals(0, fixture.local.calls)
        }

        listOf("updateAad", "update", "finish", "abort").forEach { stage ->
            val fixture = CandidateFixture()
            val key = fixture.adapter.generate(fixture.request).success()
            val operation = fixture.adapter.begin(fixture.uid, key.id).success()
            fixture.backend.failure = stage to CandidateError.TRANSPORT
            val actual =
                when (stage) {
                    "updateAad" -> fixture.adapter.updateAad(operation, byteArrayOf(1))
                    "update" -> fixture.adapter.update(operation, byteArrayOf(1))
                    "finish" -> fixture.adapter.finish(operation, byteArrayOf(1))
                    else -> fixture.adapter.abort(operation)
                }
            assertEquals(CandidateError.TRANSPORT, actual.failure())
            assertEquals(0, fixture.local.calls)
        }
    }
}

private class CandidateFixture(failGenerate: CandidateError? = null) {
    val uid = 10123
    val identity = IdentityHash.of(ByteArray(32) { 3 })
    val storePath = Files.createTempDirectory("remote-candidate-store-")
    val store = FileRemoteCandidateStore(storePath)
    val backend = FakeRemoteCandidateBackend(failGenerate)
    val local = CountingLocalKeyMint()
    val service =
        RemoteCandidateService(identity, backend, store) { RemoteKeyHandle.of(ByteArray(16) { 5 }) }
    val adapter = RemoteCandidateRouteAdapter(service, local)
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

private class FakeRemoteCandidateBackend(failGenerate: CandidateError?) : RemoteCandidateBackend {
    private val handle = RemoteKeyHandle.of(ByteArray(16) { 5 })
    private var operationId = 5
    var failure: Pair<String, CandidateError>? = failGenerate?.let { "generate" to it }

    override fun generate(command: RemoteGenerateCommand) =
        fail("generate")
            ?: CandidateResult.Success(
                RemoteKeyMaterial(
                    handle,
                    11,
                    12,
                    listOf(byteArrayOf(0x30, 1), byteArrayOf(0x30, 2)),
                    CandidateCharacteristics.foreground(),
                )
            )

    override fun get(handle: RemoteKeyHandle) = fail("get") ?: CandidateResult.Success(Unit)

    override fun list(identityHash: IdentityHash) =
        fail("list") ?: CandidateResult.Success(listOf(handle))

    override fun delete(handle: RemoteKeyHandle) = fail("delete") ?: CandidateResult.Success(Unit)

    override fun begin(handle: RemoteKeyHandle) =
        fail("begin")
            ?: CandidateResult.Success(
                RemoteOperationHandle.of(ByteArray(16) { (++operationId).toByte() })
            )

    override fun updateAad(handle: RemoteOperationHandle, input: ByteArray) =
        fail("updateAad") ?: CandidateResult.Success(Unit)

    override fun update(handle: RemoteOperationHandle, input: ByteArray) =
        fail("update") ?: CandidateResult.Success(Unit)

    override fun finish(handle: RemoteOperationHandle, input: ByteArray) =
        fail("finish") ?: CandidateResult.Success(byteArrayOf(8, 9))

    override fun abort(handle: RemoteOperationHandle) =
        fail("abort") ?: CandidateResult.Success(Unit)

    override fun peerDied() = Unit

    private fun <T> fail(stage: String): CandidateResult<T>? =
        failure?.takeIf { it.first == stage }?.let { CandidateResult.Failure(it.second) }
}

private fun <T> CandidateResult<T>.success(): T = (this as CandidateResult.Success<T>).value

private fun CandidateResult<*>.failure(): CandidateError = (this as CandidateResult.Failure).error
