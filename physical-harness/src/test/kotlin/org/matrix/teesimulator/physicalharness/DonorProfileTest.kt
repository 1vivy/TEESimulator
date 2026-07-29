package org.matrix.teesimulator.physicalharness

import java.net.InetAddress
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import org.matrix.teesimulator.twophone.SpkiPin

class DonorProfileTest {
    private val fixture = DonorProfileFixture()

    @Test
    fun acceptsOnlyBoundedAsciiProfileIdentifiers() {
        listOf("profile", "A0._-", "x".repeat(64)).forEach { profileId ->
            fixture.profile(profileId = profileId)
        }

        listOf("", "x".repeat(65), "with space", "path/name", "path\\name", "é", "line\nfeed")
            .forEach { profileId ->
                assertFailsWith<DonorProfileException.InvalidProfileId> {
                    fixture.profile(profileId = profileId)
                }
            }
    }

    @Test
    fun rejectsUnsupportedBindAddressesAndOutOfRangePorts() {
        assertFailsWith<DonorProfileException.InvalidBindAddress> {
            fixture.profile(
                bindAddress = InetAddress.getByAddress(byteArrayOf(224.toByte(), 0, 0, 1))
            )
        }
        listOf(Int.MIN_VALUE, -1, 0, 65_536, Int.MAX_VALUE).forEach { port ->
            assertFailsWith<DonorProfileException.InvalidPort> { fixture.profile(port = port) }
        }

        fixture.profile(port = 1)
        fixture.profile(port = 65_535)
    }

    @Test
    fun rejectsMalformedNonCanonicalAndExpiredIdentityCertificates() {
        val identityDer = fixture.target.certificate.encoded
        listOf(
                byteArrayOf(),
                byteArrayOf(1, 2, 3),
                identityDer + byteArrayOf(0),
                identityDer + identityDer,
            )
            .forEach { invalidDer ->
                assertFailsWith<DonorProfileException.InvalidCertificate> {
                    fixture.profile(targetIdentityCertificateDer = invalidDer)
                }
            }

        assertFailsWith<DonorProfileException.InvalidCertificate> {
            fixture.profile(now = fixture.now.plus(2, ChronoUnit.DAYS))
        }
    }

    @Test
    fun rejectsEmptyMalformedNonCanonicalAndExpiredTrustAnchors() {
        val anchorDer = fixture.targetRoot.certificate.encoded
        assertFailsWith<DonorProfileException.InvalidTrustAnchors> {
            fixture.profile(targetTrustAnchorDer = emptyList())
        }
        listOf(
                byteArrayOf(),
                byteArrayOf(1, 2, 3),
                anchorDer + byteArrayOf(0),
                anchorDer + anchorDer,
            )
            .forEach { invalidDer ->
                assertFailsWith<DonorProfileException.InvalidCertificate> {
                    fixture.profile(targetTrustAnchorDer = listOf(invalidDer))
                }
            }
        assertFailsWith<DonorProfileException.InvalidCertificate> {
            fixture.profile(targetTrustAnchorDer = listOf(fixture.expiredRoot.certificate.encoded))
        }
    }

    @Test
    fun requiresTheExactTargetIdentityCertificateToMatchTheExpectedTargetPin() {
        assertFailsWith<DonorProfileException.TargetPinMismatch> {
            fixture.profile(expectedTargetPin = SpkiPin.from(fixture.otherTarget.certificate))
        }
    }

    @Test
    fun defensivelyCopiesAddressCertificateAnchorsAndFingerprintBytes() {
        val identityDer = fixture.target.certificate.encoded
        val anchorDer = fixture.targetRoot.certificate.encoded
        val profile =
            fixture.profile(
                targetIdentityCertificateDer = identityDer,
                targetTrustAnchorDer = listOf(anchorDer),
            )
        val expectedIdentity = identityDer.copyOf()
        val expectedAnchor = anchorDer.copyOf()
        val expectedAddress = profile.bindAddress.address
        val expectedFingerprint = profile.fingerprint

        identityDer.fill(0)
        anchorDer.fill(0)
        profile.targetIdentityCertificateDer.fill(0)
        profile.targetTrustAnchorDer.single().fill(0)
        profile.bindAddress.address.fill(0)
        profile.fingerprint.fill(0)

        assertContentEquals(expectedIdentity, profile.targetIdentityCertificateDer)
        assertContentEquals(expectedAnchor, profile.targetTrustAnchorDer.single())
        assertContentEquals(expectedAddress, profile.bindAddress.address)
        assertContentEquals(expectedFingerprint, profile.fingerprint)
    }

    @Test
    fun fingerprintIsDeterministicAndCoversEveryCanonicalPublicField() {
        val original = fixture.profile()
        assertContentEquals(original.fingerprint, fixture.profile().fingerprint)

        val variants =
            listOf(
                fixture.profile(profileId = "other-profile"),
                fixture.profile(bindAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 2))),
                fixture.profile(port = 44_444),
                fixture.profile(expectedDonorPin = SpkiPin.from(fixture.otherDonor.certificate)),
                fixture.profile(
                    expectedTargetPin = SpkiPin.from(fixture.otherTarget.certificate),
                    targetIdentityCertificateDer = fixture.otherTarget.certificate.encoded,
                ),
                fixture.profile(
                    targetTrustAnchorDer =
                        listOf(
                            fixture.targetRoot.certificate.encoded,
                            fixture.otherRoot.certificate.encoded,
                        )
                ),
            )

        variants.forEach { variant ->
            assertNotEquals(original.fingerprint.toList(), variant.fingerprint.toList())
        }
    }
}

internal class DonorProfileFixture {
    val now: Instant = Instant.now()
    private val pki = TlsTestPki()
    val donorRoot = pki.root("donor-root")
    val donor = pki.leaf("donor", donorRoot, server = true)
    val otherDonor = pki.leaf("other-donor", donorRoot, server = true)
    val targetRoot = pki.root("target-root")
    val target = pki.leaf("target", targetRoot, server = false)
    val otherTarget = pki.leaf("other-target", targetRoot, server = false)
    val otherRoot = pki.root("other-root")
    val expiredRoot =
        pki.root("expired-root", now.minus(3, ChronoUnit.DAYS), now.minus(2, ChronoUnit.DAYS))

    fun profile(
        profileId: String = "approved.profile",
        bindAddress: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)),
        port: Int = 43_210,
        expectedDonorPin: SpkiPin = SpkiPin.from(donor.certificate),
        expectedTargetPin: SpkiPin = SpkiPin.from(target.certificate),
        targetIdentityCertificateDer: ByteArray = target.certificate.encoded,
        targetTrustAnchorDer: List<ByteArray> = listOf(targetRoot.certificate.encoded),
        now: Instant = this.now,
    ): DonorProfile =
        DonorProfile.create(
            profileId,
            bindAddress,
            port,
            expectedDonorPin,
            expectedTargetPin,
            targetIdentityCertificateDer,
            targetTrustAnchorDer,
            now,
        )
}
