package org.matrix.TEESimulator.rka.identity

import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Properties
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CandidateIdentityCanonicalizerTest {
    private val signerA = fixture("current-a.der.hex")
    private val signerB = fixture("current-b.der.hex")

    @Test
    fun sharedUidSigningRotation() {
        val original =
            canonical(
                pkg("zeta.synthetic", 0u, signerA, history = listOf(signerB, signerA)),
                pkg("éclair.synthetic", ULong.MAX_VALUE, signerA),
            )
        val permuted =
            canonical(
                pkg("éclair.synthetic", ULong.MAX_VALUE, signerA),
                pkg("zeta.synthetic", 0u, signerA, history = listOf(signerA)),
            )

        assertArrayEquals(original.aaidDer(), permuted.aaidDer())
        assertArrayEquals(original.aaidHash(), permuted.aaidHash())
        assertFalse(original.policyLineageHash().contentEquals(permuted.policyLineageHash()))
        assertFalse(original.identityHash().contentEquals(permuted.identityHash()))

        val versionChanged =
            canonical(
                pkg("zeta.synthetic", 1u, signerA),
                pkg("éclair.synthetic", ULong.MAX_VALUE, signerA),
            )
        assertFalse(original.aaidDer().contentEquals(versionChanged.aaidDer()))

        val signerChanged =
            canonical(
                pkg("zeta.synthetic", 0u, signerB),
                pkg("éclair.synthetic", ULong.MAX_VALUE, signerB),
            )
        assertFalse(original.aaidDer().contentEquals(signerChanged.aaidDer()))
        assertEquals(
            listOf("zeta.synthetic", "éclair.synthetic"),
            original.packages.map { it.name },
        )
    }

    @Test
    fun rejectsMalformedIncompleteOrAmbiguousAuthorityData() {
        rejects(IdentityError.DUPLICATE_PACKAGE) {
            canonical(pkg("same", 1u, signerA), pkg("same", 1u, signerA))
        }
        rejects(IdentityError.DUPLICATE_CURRENT_SIGNER) {
            canonical(pkg("same", 1u, signerA, signerA))
        }
        rejects(IdentityError.MISSING_CURRENT_SIGNER) { canonical(pkg("same", 1u)) }
        rejects(IdentityError.MALFORMED_SIGNER) {
            canonical(pkg("same", 1u, byteArrayOf(0x30, 0x00)))
        }
        rejects(IdentityError.INCONSISTENT_SHARED_UID_SIGNERS) {
            canonical(pkg("one", 1u, signerA), pkg("two", 1u, signerB))
        }
        rejects(IdentityError.INVALID_PACKAGE_NAME) { canonical(pkg("\uD800", 1u, signerA)) }
        rejects(IdentityError.LIMIT_EXCEEDED) { canonical(pkg("x".repeat(256), 1u, signerA)) }
        rejects(IdentityError.LIMIT_EXCEEDED) { canonical(*Array(17) { pkg("p$it", 1u, signerA) }) }
        rejects(IdentityError.LIMIT_EXCEEDED) {
            canonical(pkg("same", 1u, *Array(9) { signerA + it.toByte() }))
        }
        rejects(IdentityError.LIMIT_EXCEEDED) {
            canonical(pkg("same", 1u, signerA, history = List(17) { signerA + it.toByte() }))
        }
        rejects(IdentityError.DUPLICATE_LINEAGE_SIGNER) {
            canonical(pkg("same", 1u, signerA, history = listOf(signerA, signerA)))
        }
        rejects(IdentityError.INVALID_UID) {
            CandidateIdentityCanonicalizer.canonicalize(
                11,
                1_000_042,
                listOf(pkg("same", 1u, signerA)),
                1,
            )
        }
    }

    @Test
    fun independentSyntheticFixturePinsDerCborHashesAndBundleDigest() {
        val directory = candidateFixtureDirectory()
        val properties =
            Properties().apply {
                directory.resolve("vector.properties").reader(Charsets.UTF_8).use(::load)
            }
        val files =
            listOf(
                "current-a.der.hex",
                "current-b.der.hex",
                "lineage-old.der.hex",
                "vector.properties",
            )
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("candidate-identity-vector-v1\u0000".toByteArray())
        files.sorted().forEach {
            digest.update(it.toByteArray())
            digest.update(0)
            digest.update(directory.resolve(it).readBytes())
        }
        assertEquals(directory.resolve("fixture.sha256").readText().trim(), digest.digest().hex())

        val current =
            properties.getProperty("current_signers").split(',').map {
                directory.resolve(it).readText().trim().decodeHex()
            }
        val history =
            properties.getProperty("signing_history").split(',').map {
                directory.resolve(it).readText().trim().decodeHex()
            }
        (current + history).forEach {
            CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream())
        }
        val names = properties.getProperty("packages").split(',')
        val versions = properties.getProperty("versions").split(',').map(String::toULong)
        val snapshot =
            CandidateIdentityCanonicalizer.canonicalize(
                properties.getProperty("android_user").toInt(),
                properties.getProperty("uid").toInt(),
                names.indices.map {
                    RawPackageIdentity(names[it], versions[it], current.reversed(), history)
                },
                19,
            )
        assertEquals(properties.getProperty("aaid_der"), snapshot.aaidDer().hex())
        assertEquals(properties.getProperty("aaid_hash"), snapshot.aaidHash().hex())
        assertEquals(
            properties.getProperty("policy_lineage_hash"),
            snapshot.policyLineageHash().hex(),
        )
        assertEquals(properties.getProperty("identity_hash"), snapshot.identityHash().hex())
    }

    private fun canonical(vararg packages: RawPackageIdentity): CandidateIdentitySnapshot =
        CandidateIdentityCanonicalizer.canonicalize(10, 1_000_042, packages.toList(), 7)

    private fun pkg(
        name: String,
        version: ULong,
        vararg current: ByteArray,
        history: List<ByteArray> = current.toList(),
    ) = RawPackageIdentity(name, version, current.toList(), history)

    private fun rejects(error: IdentityError, block: () -> Unit) {
        try {
            block()
            fail("expected $error")
        } catch (e: CandidateIdentityException) {
            assertEquals(error, e.error)
        }
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    private fun String.decodeHex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun fixture(name: String) =
        candidateFixtureDirectory().resolve(name).readText().trim().decodeHex()
}

class CandidateIdentityDriftTest {
    private val signer =
        candidateFixtureDirectory()
            .resolve("current-a.der.hex")
            .readText()
            .trim()
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    @Test
    fun everyInFlightFieldDriftSuppressesAndQuarantinesExactlyOnce() {
        val initial = raw("synthetic.app", 1u, signer)
        val variants =
            listOf(
                initial.copy(androidUser = 11),
                initial.copy(uid = initial.uid + 1),
                raw("synthetic.other", 1u, signer),
                raw("synthetic.app", 2u, signer),
                raw("synthetic.app", 1u, byteArrayOf(0x30, 0x00)),
                initial.copy(
                    packages =
                        listOf(
                            RawPackageIdentity(
                                "synthetic.app",
                                1u,
                                listOf(signer),
                                listOf(signer, byteArrayOf(1)),
                            )
                        )
                ),
            )
        variants.forEach { changed ->
            val authority = SequenceAuthority(initial, changed)
            val gate = CandidateIdentityGate({ initial.uid }, authority)
            val admission = gate.admitRemote()
            val destroyed = AtomicInteger()
            val quarantined = AtomicInteger()
            val pending = PendingCandidateResponse("secret-chain") { destroyed.incrementAndGet() }

            val pool = Executors.newFixedThreadPool(8)
            val start = CountDownLatch(1)
            val results =
                (0 until 8).map {
                    pool.submit<IdentityExposure<String>> {
                        start.await()
                        gate.expose(admission, pending) { quarantined.incrementAndGet() }
                    }
                }
            start.countDown()
            val values = results.map { it.get() }
            pool.shutdown()

            assertTrue(
                values.all {
                    it is IdentityExposure.Rejected && it.error == IdentityError.IDENTITY_DRIFT
                }
            )
            assertEquals(1, destroyed.get())
            assertEquals(1, quarantined.get())
        }
    }

    @Test
    fun binderUidIsCapturedBeforeAuthorityWorkAndQueryFailureIsDrift() {
        val caller = AtomicInteger(1_000_042)
        val raw = raw("synthetic.app", 1u, signer)
        val authority =
            object : CandidateIdentityAuthority {
                private val calls = AtomicInteger()

                override fun snapshot(uid: Int, epoch: Long): AuthoritativeIdentity {
                    caller.set(2_000_042)
                    if (calls.incrementAndGet() > 1)
                        throw IllegalStateException("package manager died")
                    assertEquals(1_000_042, uid)
                    return raw
                }
            }
        val gate = CandidateIdentityGate(caller::get, authority)
        val admission = gate.admitRemote()
        val result = gate.expose(admission, PendingCandidateResponse("chain") {}) {}
        assertTrue(result is IdentityExposure.Rejected)
        assertEquals(IdentityError.IDENTITY_DRIFT, (result as IdentityExposure.Rejected).error)
    }

    @Test
    fun stableSnapshotExposesOnlyOnce() {
        val raw = raw("synthetic.app", 1u, signer)
        val gate = CandidateIdentityGate({ raw.uid }, SequenceAuthority(raw, raw))
        val admission = gate.admitRemote()
        assertTrue(gate.revalidateForRemote(admission))
        val first = gate.expose(admission, PendingCandidateResponse("chain") {}) {}
        val second = gate.expose(admission, PendingCandidateResponse("chain") {}) {}
        assertEquals("chain", (first as IdentityExposure.Exposed).value)
        assertEquals(IdentityError.STALE_ADMISSION, (second as IdentityExposure.Rejected).error)
    }

    private fun raw(name: String, version: ULong, signer: ByteArray) =
        AuthoritativeIdentity(
            androidUser = 10,
            uid = 1_000_042,
            packages = listOf(RawPackageIdentity(name, version, listOf(signer), listOf(signer))),
        )

    private class SequenceAuthority(
        private val first: AuthoritativeIdentity,
        private val later: AuthoritativeIdentity,
    ) : CandidateIdentityAuthority {
        private val calls = AtomicInteger()

        override fun snapshot(uid: Int, epoch: Long): AuthoritativeIdentity =
            if (calls.incrementAndGet() == 1) first else later
    }
}

private fun candidateFixtureDirectory() =
    generateSequence(File(requireNotNull(System.getProperty("user.dir")))) { it.parentFile }
        .map { it.resolve("two-phone/src/test/resources/candidate-identity") }
        .first(File::isDirectory)
