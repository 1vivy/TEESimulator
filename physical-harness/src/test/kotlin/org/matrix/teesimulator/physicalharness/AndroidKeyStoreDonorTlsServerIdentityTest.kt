package org.matrix.teesimulator.physicalharness

import java.security.PrivateKey
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.matrix.teesimulator.twophone.SpkiPin

class AndroidKeyStoreDonorTlsServerIdentityTest {
    private val now = Instant.parse("2026-07-25T12:34:56Z")
    private val pki = DonorTlsServerIdentityTestPki(now)

    @Test
    fun fixedAliasIsSeparateFromStateAndDonatedKeyAliases() {
        assertEquals("teesim_donor_tls_server_v1", AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS)
        assertNotEquals(
            AndroidKeyStoreHandleMac.KEY_ALIAS,
            AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS,
        )
        assertFalse(
            DonorKeyAliasPolicy.isOwnedAlias(AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS)
        )
    }

    @Test
    fun explicitProvisionGeneratesConfiguredIdentityAndExportsOnlyPublicMaterial() {
        val identity = pki.selfSigned()
        val backend = validBackend(aliasPresent = false, identity = identity)
        val serialBytes = ByteArray(16) { 0xff.toByte() }

        val provisioned =
            AndroidKeyStoreDonorTlsServerIdentity.provisionNew(
                now,
                TestFixedSecureRandom(ByteArray(16), serialBytes),
                backend,
            )

        assertEquals(AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS, provisioned.alias)
        assertEquals(1, backend.generateCount)
        assertEquals(0, backend.deleteCount)
        val spec = assertNotNull(backend.generationSpec)
        assertEquals(setOf(DonorTlsServerKeyPurpose.SIGN), spec.purposes)
        assertEquals("secp256r1", spec.curve)
        assertEquals("SHA-256", spec.digest)
        assertFalse(spec.userAuthenticationRequired)
        assertFalse(spec.strongBoxBacked)
        assertNull(spec.attestationChallenge)
        assertEquals(X500Principal("CN=TEESimulator Donor TLS v1"), spec.certificateSubject)
        assertTrue(spec.certificateSerialNumber.signum() > 0)
        assertTrue(spec.certificateSerialNumber.bitLength() <= 128)
        assertEquals(now.minus(1, ChronoUnit.DAYS), spec.certificateNotBefore.toInstant())
        assertEquals(
            now.atZone(ZoneOffset.UTC).plusYears(20).toInstant(),
            spec.certificateNotAfter.toInstant(),
        )
        assertContentEquals(identity.certificate.encoded, provisioned.leafCertificateDer)
        assertEquals(1, provisioned.certificateChainDer.size)
        assertContentEquals(identity.certificate.encoded, provisioned.certificateChainDer.single())
        assertEquals(SpkiPin.from(identity.certificate), provisioned.pin)
        assertEquals(2, backend.signedInputs.size + backend.verifiedInputs.size)
        assertContentEquals(PROBE, backend.signedInputs.single())
        assertContentEquals(PROBE, backend.verifiedInputs.single())
        assertNoPrivateKeyGetter(provisioned.javaClass)
    }

    @Test
    fun provisioningRefusesCollisionWithoutMutation() {
        val backend = validBackend(aliasPresent = true)

        assertFailsWith<DonorTlsServerIdentityException.AliasAlreadyExists> {
            AndroidKeyStoreDonorTlsServerIdentity.provisionNew(
                now,
                TestFixedSecureRandom(ByteArray(16) { 1 }),
                backend,
            )
        }

        assertTrue(backend.aliasPresent)
        assertEquals(0, backend.generateCount)
        assertEquals(0, backend.deleteCount)
        assertEquals(
            listOf("contains:${AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS}"),
            backend.calls,
        )
    }

    @Test
    fun openRefusesMissingIdentityWithoutProvisioningOrCleanup() {
        val backend = validBackend(aliasPresent = false)

        assertFailsWith<DonorTlsServerIdentityException.IdentityNotFound> {
            AndroidKeyStoreDonorTlsServerIdentity.openExisting(
                SpkiPin.from(pki.selfSigned().certificate),
                now,
                backend,
            )
        }

        assertEquals(0, backend.generateCount)
        assertEquals(0, backend.deleteCount)
        assertEquals(
            listOf("contains:${AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS}"),
            backend.calls,
        )
    }

    @Test
    fun openRejectsWrongKeyTypeAlgorithmAndExportability() {
        listOf(
                validBackend(key = null),
                validBackend(key = TestNonPrivateKey),
                validBackend(key = TestNonExportablePrivateKey("RSA")),
                validBackend(key = pki.selfSigned().keyPair.private),
            )
            .forEach { backend ->
                assertFailsWith<DonorTlsServerIdentityException.InvalidKey> {
                    openWithActualPin(backend)
                }
                assertEquals(0, backend.deleteCount)
            }
    }

    @Test
    fun openAcceptsOnlyTrustedEnvironmentSecurityLevel() {
        listOf(
                BackendSecurityLevel.SOFTWARE,
                BackendSecurityLevel.STRONGBOX,
                BackendSecurityLevel.UNKNOWN,
            )
            .forEach { level ->
                val backend = validBackend(securityLevel = level)
                assertFailsWith<DonorTlsServerIdentityException.UntrustedSecurityLevel> {
                    openWithActualPin(backend)
                }
            }

        openWithActualPin(validBackend(securityLevel = BackendSecurityLevel.TRUSTED_ENVIRONMENT))
    }

    @Test
    fun openRejectsEmptyAndNonX509CertificateChains() {
        assertFailsWith<DonorTlsServerIdentityException.InvalidCertificate> {
            openWithActualPin(validBackend(certificateChain = emptyList()))
        }
        val identity = pki.selfSigned()
        assertFailsWith<DonorTlsServerIdentityException.InvalidCertificate> {
            openWithActualPin(
                validBackend(
                    identity = identity,
                    certificateChain = listOf(TestNonX509Certificate(identity.keyPair.public)),
                )
            )
        }
    }

    @Test
    fun openRejectsExpiredAndNotYetValidLeafCertificatesAtSuppliedTime() {
        val expired =
            pki.selfSigned(
                notBefore = now.minus(2, ChronoUnit.DAYS),
                notAfter = now.minus(1, ChronoUnit.SECONDS),
            )
        val notYetValid =
            pki.selfSigned(
                notBefore = now.plus(1, ChronoUnit.SECONDS),
                notAfter = now.plus(2, ChronoUnit.DAYS),
            )

        listOf(expired, notYetValid).forEach { identity ->
            assertFailsWith<DonorTlsServerIdentityException.InvalidCertificate> {
                openWithActualPin(validBackend(identity = identity))
            }
        }
    }

    @Test
    fun openRejectsCertificateNotSignedByItsOwnPublicKey() {
        val identity = pki.signedByAnotherKey()

        assertFailsWith<DonorTlsServerIdentityException.InvalidCertificate> {
            openWithActualPin(validBackend(identity = identity))
        }
    }

    @Test
    fun openRejectsEcKeyWhoseParametersAreNotP256() {
        val identity = pki.selfSigned(curve = DonorTlsServerIdentityTestPki.P384)

        assertFailsWith<DonorTlsServerIdentityException.InvalidCertificate> {
            openWithActualPin(validBackend(identity = identity))
        }
    }

    @Test
    fun openRejectsProbeSigningAndVerificationFailures() {
        val signFailure = validBackend().apply { signFailure = IllegalStateException("synthetic") }
        assertFailsWith<DonorTlsServerIdentityException.ProbeFailure> {
            openWithActualPin(signFailure)
        }

        val verifyFailure = validBackend().apply { verifyResult = false }
        assertFailsWith<DonorTlsServerIdentityException.ProbeFailure> {
            openWithActualPin(verifyFailure)
        }
    }

    @Test
    fun openRejectsUnexpectedCanonicalSpkiPin() {
        val backend = validBackend()
        val otherPin = SpkiPin.from(pki.selfSigned().certificate)

        assertFailsWith<DonorTlsServerIdentityException.PinMismatch> {
            AndroidKeyStoreDonorTlsServerIdentity.openExisting(otherPin, now, backend)
        }

        assertEquals(0, backend.generateCount)
        assertEquals(0, backend.deleteCount)
    }

    @Test
    fun generatedValidationFailureCleansUpOnlyTheNewAlias() {
        val backend =
            validBackend(aliasPresent = false, securityLevel = BackendSecurityLevel.SOFTWARE)

        assertFailsWith<DonorTlsServerIdentityException.UntrustedSecurityLevel> {
            AndroidKeyStoreDonorTlsServerIdentity.provisionNew(
                now,
                TestFixedSecureRandom(ByteArray(16) { 1 }),
                backend,
            )
        }

        assertFalse(backend.aliasPresent)
        assertEquals(1, backend.generateCount)
        assertEquals(1, backend.deleteCount)
        assertEquals(
            "delete:${AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS}",
            backend.calls.last(),
        )
    }

    @Test
    fun cleanupFailureIsSuppressedOnGeneratedValidationFailure() {
        val cleanupFailure = IllegalStateException("synthetic cleanup")
        val backend =
            validBackend(aliasPresent = false, securityLevel = BackendSecurityLevel.SOFTWARE)
                .apply { deleteFailure = cleanupFailure }

        val failure =
            assertFailsWith<DonorTlsServerIdentityException.UntrustedSecurityLevel> {
                AndroidKeyStoreDonorTlsServerIdentity.provisionNew(
                    now,
                    TestFixedSecureRandom(ByteArray(16) { 1 }),
                    backend,
                )
            }

        val suppressed =
            assertIs<DonorTlsServerIdentityException.BackendFailure>(failure.suppressed.single())
        assertSame(cleanupFailure, suppressed.cause)
        assertTrue(backend.aliasPresent)
        assertEquals(1, backend.deleteCount)
    }

    @Test
    fun backendFailuresAreTypedAndIdentifierFree() {
        val cause = IllegalStateException("synthetic")
        val backend = validBackend().apply { containsFailure = cause }

        val failure =
            assertFailsWith<DonorTlsServerIdentityException.BackendFailure> {
                openWithActualPin(backend)
            }

        assertSame(cause, failure.cause)
        assertFalse(
            failure.message.orEmpty().contains(AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS)
        )
    }

    @Test
    fun openedIdentityCarriesDefensiveJsseMaterialWithoutPrivateKeyGetter() {
        val identity = pki.selfSigned()
        val password = "provider-password".toCharArray()
        val backend = validBackend(identity = identity, keyPassword = password)

        val opened =
            AndroidKeyStoreDonorTlsServerIdentity.openExisting(
                SpkiPin.from(identity.certificate),
                now,
                backend,
            )
        password.fill('x')

        assertEquals(AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS, opened.alias)
        assertSame(backend.providerKeyStore, opened.keyStore)
        assertContentEquals("provider-password".toCharArray(), opened.keyPassword)
        opened.keyPassword?.fill('y')
        assertContentEquals("provider-password".toCharArray(), opened.keyPassword)
        assertEquals(SpkiPin.from(identity.certificate), opened.pin)
        val firstChain = opened.certificateChainDer
        firstChain.single().fill(0)
        assertContentEquals(identity.certificate.encoded, opened.certificateChainDer.single())
        assertNoPrivateKeyGetter(opened.javaClass)
        assertEquals(0, backend.generateCount)
        assertEquals(0, backend.deleteCount)
    }

    @Test
    fun provisionedPublicDerIsDefensive() {
        val identity = pki.selfSigned()
        val provisioned =
            AndroidKeyStoreDonorTlsServerIdentity.provisionNew(
                now,
                TestFixedSecureRandom(ByteArray(16) { 1 }),
                validBackend(aliasPresent = false, identity = identity),
            )

        provisioned.leafCertificateDer.fill(0)
        provisioned.certificateChainDer.single().fill(0)

        assertContentEquals(identity.certificate.encoded, provisioned.leafCertificateDer)
        assertContentEquals(identity.certificate.encoded, provisioned.certificateChainDer.single())
    }

    @Test
    fun concurrentProvisionAllowsOneGenerationAndOneCollision() {
        val backend = validBackend(aliasPresent = false)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val attempts =
                List(2) {
                    executor.submit<Throwable?> {
                        start.await()
                        runCatching {
                                AndroidKeyStoreDonorTlsServerIdentity.provisionNew(
                                    now,
                                    TestFixedSecureRandom(ByteArray(16) { 1 }),
                                    backend,
                                )
                            }
                            .exceptionOrNull()
                    }
                }
            start.countDown()

            val failures = attempts.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, failures.count { it == null })
            assertEquals(
                1,
                failures.count { it is DonorTlsServerIdentityException.AliasAlreadyExists },
            )
            assertEquals(1, backend.generateCount)
            assertEquals(0, backend.deleteCount)
        } finally {
            executor.shutdownNow()
        }
    }

    private fun openWithActualPin(
        backend: FakeDonorTlsServerIdentityBackend
    ): OpenedDonorTlsServerIdentity {
        val certificate =
            backend.certificateChain.firstOrNull() as? java.security.cert.X509Certificate
        val pin = certificate?.let(SpkiPin::from) ?: SpkiPin.from(pki.selfSigned().certificate)
        return AndroidKeyStoreDonorTlsServerIdentity.openExisting(pin, now, backend)
    }

    private fun validBackend(
        aliasPresent: Boolean = true,
        identity: DonorTlsTestIdentity = pki.selfSigned(),
        key: java.security.Key? = TestNonExportablePrivateKey(),
        securityLevel: BackendSecurityLevel = BackendSecurityLevel.TRUSTED_ENVIRONMENT,
        certificateChain: List<java.security.cert.Certificate> = listOf(identity.certificate),
        keyPassword: CharArray? = null,
    ): FakeDonorTlsServerIdentityBackend =
        FakeDonorTlsServerIdentityBackend(
            aliasPresent = aliasPresent,
            key = key,
            securityLevel = securityLevel,
            certificateChain = certificateChain,
            keyPassword = keyPassword,
        )

    private fun assertNoPrivateKeyGetter(type: Class<*>) {
        assertFalse(type.methods.any { PrivateKey::class.java.isAssignableFrom(it.returnType) })
    }

    private companion object {
        val PROBE = "TEESimulator\u0000donor-tls-server-identity\u0000v1".encodeToByteArray()
    }
}
