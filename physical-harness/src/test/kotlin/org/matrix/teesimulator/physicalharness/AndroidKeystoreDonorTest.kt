package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec

class AndroidKeystoreDonorTest {
    private val ownIdentity = identity("org.example.donor", byteArrayOf(1, 2, 3))
    private val otherCaller = WireCallerIdentity("different-signer", "different-app")
    private val challenge = byteArrayOf(9, 8, 7)

    @Test
    fun successfulLifecycleReturnsDefensiveMetadataEmptyUpdatesAndFinishOnlySignature() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)

        val generated = donor.generate("signing-key", challenge, ownIdentity.wireIdentity)
        val metadata = donor.metadata("signing-key", ownIdentity.wireIdentity)
        val operation = donor.begin("signing-key", ownIdentity.wireIdentity)
        val updateOutput = donor.update(operation, ownIdentity.wireIdentity, byteArrayOf(1, 2))
        val finishOutput = donor.finish(operation, ownIdentity.wireIdentity, byteArrayOf(3, 4))

        assertEquals(KeyState.ACTIVE, generated.state)
        assertEquals(
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            ),
            generated.keySpec,
        )
        assertContentEquals(challenge, generated.attestationChallenge)
        assertContentEquals(generated.publicKey, metadata.publicKey)
        assertTrue(updateOutput.isEmpty())
        assertContentEquals(FakeSignOperation.SIGNATURE, finishOutput)
        assertEquals(2, backend.operations.single().inputs.size)
        assertContentEquals(byteArrayOf(1, 2), backend.operations.single().inputs[0])
        assertContentEquals(byteArrayOf(3, 4), backend.operations.single().inputs[1])

        val expectedPublicKey = generated.publicKey
        val expectedCertificate = generated.certificateChain.single()
        generated.attestationChallenge.fill(0)
        generated.publicKey.fill(0)
        generated.certificateChain.single().fill(0)
        assertContentEquals(challenge, generated.attestationChallenge)
        assertContentEquals(expectedPublicKey, generated.publicKey)
        assertContentEquals(expectedCertificate, generated.certificateChain.single())
        assertFailsWith<AndroidKeystoreDonorException.OperationNotFound> {
            donor.update(operation, ownIdentity.wireIdentity, byteArrayOf(5))
        }
    }

    @Test
    fun wrongCallerIsRejectedBeforeEveryBackendKeyOrOperationAccess() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        donor.generate("signing-key", challenge, ownIdentity.wireIdentity)
        val operation = donor.begin("signing-key", ownIdentity.wireIdentity)
        backend.calls.clear()
        backend.operations.single().calls.clear()

        val attempts =
            listOf<() -> Unit>(
                { donor.generate("other-key", challenge, otherCaller) },
                { donor.metadata("signing-key", otherCaller) },
                { donor.delete("signing-key", otherCaller) },
                { donor.begin("signing-key", otherCaller) },
                { donor.update(operation, otherCaller, byteArrayOf(1)) },
                { donor.finish(operation, otherCaller, byteArrayOf(1)) },
                { donor.abort(operation, otherCaller) },
            )
        attempts.forEach { attempt ->
            assertFailsWith<AndroidKeystoreDonorException.WrongCaller> { attempt() }
        }

        assertTrue(backend.calls.isEmpty())
        assertTrue(backend.operations.single().calls.isEmpty())
    }

    @Test
    fun everyBoundaryFreshlyResolvesOwnIdentity() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        var resolvedIdentity = ownIdentity
        var resolutions = 0
        val donor =
            AndroidKeystoreDonor(
                identityResolver = {
                    resolutions += 1
                    resolvedIdentity
                },
                backend = backend,
            )
        donor.generate("signing-key", challenge, ownIdentity.wireIdentity)
        val operation = donor.begin("signing-key", ownIdentity.wireIdentity)
        resolvedIdentity = identity("org.example.changed", byteArrayOf(4, 5, 6))

        assertFailsWith<AndroidKeystoreDonorException.WrongCaller> {
            donor.update(operation, ownIdentity.wireIdentity, byteArrayOf(1))
        }
        assertEquals(3, resolutions)
        assertTrue(backend.operations.single().calls.isEmpty())
    }

    @Test
    fun abortAndDeleteAbortBackendOperationsAndRemoveProcessHandles() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        donor.generate("signing-key", challenge, ownIdentity.wireIdentity)
        val explicitlyAborted = donor.begin("signing-key", ownIdentity.wireIdentity)
        donor.abort(explicitlyAborted, ownIdentity.wireIdentity)
        val deletedOperation = donor.begin("signing-key", ownIdentity.wireIdentity)

        donor.delete("signing-key", ownIdentity.wireIdentity)

        assertEquals(1, backend.operations[0].abortCount)
        assertEquals(1, backend.operations[1].abortCount)
        assertEquals(listOf("signing-key"), backend.deletedAliases)
        assertFailsWith<AndroidKeystoreDonorException.OperationNotFound> {
            donor.finish(deletedOperation, ownIdentity.wireIdentity, byteArrayOf())
        }
        assertFailsWith<AndroidKeystoreDonorException.KeyNotFound> {
            donor.metadata("signing-key", ownIdentity.wireIdentity)
        }
    }

    @Test
    fun processLocalOperationCannotResumeInANewCoordinator() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val first = donor(backend)
        first.generate("signing-key", challenge, ownIdentity.wireIdentity)
        val operation = first.begin("signing-key", ownIdentity.wireIdentity)
        val restarted = donor(backend)

        restarted.metadata("signing-key", ownIdentity.wireIdentity)
        assertFailsWith<AndroidKeystoreDonorException.OperationNotFound> {
            restarted.update(operation, ownIdentity.wireIdentity, byteArrayOf(1))
        }
        assertTrue(backend.operations.single().calls.isEmpty())
    }

    @Test
    fun backendOperationErrorTerminalizesAndAbortsOperation() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        donor.generate("signing-key", challenge, ownIdentity.wireIdentity)
        val operation = donor.begin("signing-key", ownIdentity.wireIdentity)
        backend.operations.single().updateFailure =
            AndroidKeystoreDonorException.BackendFailure(IllegalStateException("synthetic"))

        assertFailsWith<AndroidKeystoreDonorException.BackendFailure> {
            donor.update(operation, ownIdentity.wireIdentity, byteArrayOf(1))
        }
        assertEquals(1, backend.operations.single().abortCount)
        assertFailsWith<AndroidKeystoreDonorException.OperationNotFound> {
            donor.finish(operation, ownIdentity.wireIdentity, byteArrayOf())
        }
    }

    @Test
    fun rejectsExistingAliasAndInvalidBoundedInputs() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        donor.generate("signing-key", challenge, ownIdentity.wireIdentity)

        assertFailsWith<AndroidKeystoreDonorException.AliasAlreadyExists> {
            donor.generate("signing-key", challenge, ownIdentity.wireIdentity)
        }
        listOf("", " ", "a".repeat(AndroidKeystoreDonor.MAX_ALIAS_UTF8_BYTES + 1)).forEach { alias
            ->
            assertFailsWith<AndroidKeystoreDonorException.InvalidAlias> {
                donor.metadata(alias, ownIdentity.wireIdentity)
            }
        }
        listOf(byteArrayOf(), ByteArray(AndroidKeystoreDonor.MAX_ATTESTATION_CHALLENGE_BYTES + 1))
            .forEach { invalidChallenge ->
                assertFailsWith<AndroidKeystoreDonorException.InvalidChallenge> {
                    donor.generate("unused", invalidChallenge, ownIdentity.wireIdentity)
                }
            }
    }

    @Test
    fun reconciliationOwnedAliasesUseOnlyTheCanonicalDonorPrefix() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        val owned = DonorKeyAliasPolicy.aliasFor(testUuid(500))
        val malformedOwned = "teesim_donor_key_v1_not-a-uuid"
        backend.put(owned, validMaterial(challenge))
        backend.put(AndroidKeyStoreHandleMac.KEY_ALIAS, validMaterial(challenge))
        backend.put(malformedOwned, validMaterial(challenge))
        backend.put("unrelated", validMaterial(challenge))

        assertEquals(setOf(owned, malformedOwned), donor.ownedAliases())
    }

    @Test
    fun reconciliationInspectionDistinguishesAbsentVerifiedAndRejected() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        val alias = DonorKeyAliasPolicy.aliasFor(testUuid(501))
        donor.generate(alias, challenge, ownIdentity.wireIdentity)

        assertIs<DurableKeyInspection.Absent>(
            donor.inspect(
                DonorKeyAliasPolicy.aliasFor(testUuid(502)),
                ownIdentity.wireIdentity,
                null,
            )
        )
        val verified =
            assertIs<DurableKeyInspection.Verified>(
                donor.inspect(alias, ownIdentity.wireIdentity, challenge)
            )
        assertContentEquals(challenge, verified.metadata.attestationChallenge)
        assertIs<DurableKeyInspection.Rejected>(
            donor.inspect(alias, ownIdentity.wireIdentity, byteArrayOf(1, 2, 3))
        )
    }

    @Test
    fun exactDeleteNeverDeletesReboundMaterialAndAbortsOperationsOnlyOnMatch() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val donor = donor(backend)
        val alias = DonorKeyAliasPolicy.aliasFor(testUuid(503))
        val expected = donor.generate(alias, challenge, ownIdentity.wireIdentity)
        val operation = donor.begin(alias, ownIdentity.wireIdentity)
        val rebound =
            org.matrix.teesimulator.twophone.WireKeyMetadata(
                KeyState.ACTIVE,
                expected.attestationChallenge,
                expected.publicKey.mutated(0),
                expected.certificateChain,
                expected.keySpec,
            )

        assertEquals(
            DurableDeleteOutcome.MISMATCH,
            donor.deleteIfExact(alias, ownIdentity.wireIdentity, rebound),
        )
        assertTrue(backend.hasAlias(alias))
        assertEquals(0, backend.operations.single().abortCount)

        assertEquals(
            DurableDeleteOutcome.DELETED,
            donor.deleteIfExact(alias, ownIdentity.wireIdentity, expected),
        )
        assertEquals(1, backend.operations.single().abortCount)
        assertFailsWith<AndroidKeystoreDonorException.OperationNotFound> {
            donor.abort(operation, ownIdentity.wireIdentity)
        }
    }

    @Test
    fun sharedCoordinatorPreventsReplacementBetweenExactInspectionAndDelete() {
        val backend = FakeAndroidKeyStoreBackend(::validMaterial)
        val coordinator = AndroidKeystoreDonorCoordinator()
        val first = AndroidKeystoreDonor({ ownIdentity }, backend, coordinator = coordinator)
        val second = AndroidKeystoreDonor({ ownIdentity }, backend, coordinator = coordinator)
        val alias = DonorKeyAliasPolicy.aliasFor(testUuid(504))
        val expected = first.generate(alias, challenge, ownIdentity.wireIdentity)
        backend.metadataEntered = CountDownLatch(1)
        backend.metadataRelease = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val deletion =
            pool.submit<DurableDeleteOutcome> {
                first.deleteIfExact(alias, ownIdentity.wireIdentity, expected)
            }
        assertTrue(backend.metadataEntered!!.await(5, TimeUnit.SECONDS))
        val replacementChallenge = byteArrayOf(4, 5, 6)
        val replacement =
            pool.submit<org.matrix.teesimulator.twophone.WireKeyMetadata> {
                second.generate(alias, replacementChallenge, ownIdentity.wireIdentity)
            }
        assertFalse(replacement.isDone)
        backend.metadataRelease!!.countDown()

        assertEquals(DurableDeleteOutcome.DELETED, deletion.get(5, TimeUnit.SECONDS))
        assertContentEquals(
            replacementChallenge,
            replacement.get(5, TimeUnit.SECONDS).attestationChallenge,
        )
        assertTrue(backend.hasAlias(alias))
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
    }

    @Test
    fun sharedCoordinatorPreventsFailedGenerationCleanupDeletingReplacement() {
        val backend = FakeAndroidKeyStoreBackend {
            SyntheticAndroidKeyAttestation.material(
                byteArrayOf(1),
                ownIdentity.attestationApplicationIdDer,
            )
        }
        val coordinator = AndroidKeystoreDonorCoordinator()
        val first = AndroidKeystoreDonor({ ownIdentity }, backend, coordinator = coordinator)
        val second = AndroidKeystoreDonor({ ownIdentity }, backend, coordinator = coordinator)
        val alias = DonorKeyAliasPolicy.aliasFor(testUuid(505))
        backend.deleteEntered = CountDownLatch(1)
        backend.deleteRelease = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val rejected =
            pool.submit<Result<org.matrix.teesimulator.twophone.WireKeyMetadata>> {
                runCatching { first.generate(alias, challenge, ownIdentity.wireIdentity) }
            }
        assertTrue(backend.deleteEntered!!.await(5, TimeUnit.SECONDS))
        backend.setMaterialFactory(::validMaterial)
        val replacement =
            pool.submit { second.generate(alias, challenge, ownIdentity.wireIdentity) }
        assertFalse(replacement.isDone)
        backend.deleteRelease!!.countDown()

        assertTrue(rejected.get(5, TimeUnit.SECONDS).isFailure)
        replacement.get(5, TimeUnit.SECONDS)
        assertTrue(backend.hasAlias(alias))
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
    }

    private fun donor(backend: FakeAndroidKeyStoreBackend) =
        AndroidKeystoreDonor(identityResolver = { ownIdentity }, backend = backend)

    private fun validMaterial(requestedChallenge: ByteArray) =
        SyntheticAndroidKeyAttestation.material(
            requestedChallenge,
            ownIdentity.attestationApplicationIdDer,
        )

    private fun identity(packageName: String, certificate: ByteArray) =
        CallerIdentityCanonicalizer()
            .canonicalize(listOf(CallerPackageIdentity(packageName, 1, listOf(certificate))))
}

internal class FakeAndroidKeyStoreBackend(
    private var materialFactory: (ByteArray) -> BackendKeyMaterial
) : AndroidKeyStoreBackend {
    val calls = mutableListOf<String>()
    val operations = mutableListOf<FakeSignOperation>()
    val deletedAliases = mutableListOf<String>()
    private val keys = mutableMapOf<String, BackendKeyMaterial>()
    var metadataEntered: CountDownLatch? = null
    var metadataRelease: CountDownLatch? = null
    var deleteEntered: CountDownLatch? = null
    var deleteRelease: CountDownLatch? = null

    override fun aliases(): Set<String> {
        calls += "aliases"
        return keys.keys.toSet()
    }

    override fun containsAlias(alias: String): Boolean {
        calls += "contains"
        return keys.containsKey(alias)
    }

    override fun generate(alias: String, challenge: ByteArray): BackendKeyMaterial {
        calls += "generate"
        return materialFactory(challenge).also { keys[alias] = it }
    }

    override fun metadata(alias: String): BackendKeyMaterial? {
        calls += "metadata"
        metadataEntered?.countDown()
        metadataRelease?.await(5, TimeUnit.SECONDS)
        return keys[alias]
    }

    override fun delete(alias: String) {
        calls += "delete"
        deleteEntered?.countDown()
        deleteRelease?.await(5, TimeUnit.SECONDS)
        keys.remove(alias)
        deletedAliases += alias
    }

    override fun begin(alias: String): BackendSignOperation {
        calls += "begin"
        check(keys.containsKey(alias))
        return FakeSignOperation().also(operations::add)
    }

    fun put(alias: String, material: BackendKeyMaterial) {
        keys[alias] = material
    }

    fun hasAlias(alias: String): Boolean = keys.containsKey(alias)

    fun setMaterialFactory(factory: (ByteArray) -> BackendKeyMaterial) {
        materialFactory = factory
    }
}

internal class FakeSignOperation : BackendSignOperation {
    val calls = mutableListOf<String>()
    val inputs = mutableListOf<ByteArray>()
    var abortCount = 0
    var updateFailure: RuntimeException? = null
    var finishFailure: RuntimeException? = null
    var finishResult: ByteArray = SIGNATURE.copyOf()

    override fun update(input: ByteArray) {
        calls += "update"
        updateFailure?.let { throw it }
        inputs += input.copyOf()
    }

    override fun finish(input: ByteArray): ByteArray {
        calls += "finish"
        finishFailure?.let { throw it }
        inputs += input.copyOf()
        return finishResult.copyOf()
    }

    override fun abort() {
        calls += "abort"
        abortCount += 1
    }

    companion object {
        val SIGNATURE = byteArrayOf(0x30, 0x01, 0x02)
    }
}
