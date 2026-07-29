package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CallerIdentityCanonicalizerTest {
    private val canonicalizer = CallerIdentityCanonicalizer()
    private val currentCertificate = byteArrayOf(0x01, 0x02, 0x03)
    private val historicalCertificate = byteArrayOf(0x0a, 0x0b)

    @Test
    fun matchesKnownAttestationApplicationIdDerAndDigestVector() {
        val identity =
            canonicalizer.canonicalize(
                listOf(
                    callerPackage("com.example.alpha", 7, currentCertificate),
                    callerPackage("com.example.beta", 42, historicalCertificate),
                )
            )

        assertContentEquals(
            ("3077312f30150410636f6d2e6578616d706c652e6265746102012a30160411636f6d2e" +
                    "6578616d706c652e616c70686102010731440420039058c6f2c0cb492c533b0a4d14ef" +
                    "77cc0f78abccced5287d84a1a2011cfb810420bea0b72e71bfe7f15a88c25305bf96" +
                    "a9681e34d3aabe0c9a1b7093cb32d8ff05")
                .hexBytes(),
            identity.attestationApplicationIdDer,
        )
        assertEquals(
            "56f47135d605a8a0dd89b93f4ddfab475a18a52aef1431d015e6d8704e87f806",
            identity.wireIdentity.signingCertificateDigest,
        )
        assertEquals(
            "9db88de72f8b98ba736ccd9e31d37a03861ebe65045b1fc1c68690a9794e8a7b",
            identity.wireIdentity.attestationApplicationIdDigest,
        )
        assertTrue(identity.wireIdentity.signingCertificateDigest.matches(LOWERCASE_SHA_256))
        assertTrue(identity.wireIdentity.attestationApplicationIdDigest.matches(LOWERCASE_SHA_256))
    }

    @Test
    fun packageAndSigningHistoryOrderAndDuplicateCertificatesDoNotChangeIdentity() {
        val ordered =
            canonicalizer.canonicalize(
                listOf(
                    callerPackage(
                        "com.example.alpha",
                        7,
                        currentCertificate,
                        historicalCertificate,
                        currentCertificate,
                    ),
                    callerPackage("com.example.beta", 42, historicalCertificate),
                )
            )
        val reordered =
            canonicalizer.canonicalize(
                listOf(
                    callerPackage("com.example.beta", 42, historicalCertificate),
                    callerPackage("com.example.alpha", 7, historicalCertificate, currentCertificate),
                )
            )

        assertEquals(ordered, reordered)
        assertContentEquals(
            ordered.attestationApplicationIdDer,
            reordered.attestationApplicationIdDer,
        )
        assertEquals(ordered.wireIdentity, reordered.wireIdentity)
    }

    @Test
    fun numericTargetAndDonorUidsAreNotCanonicalIdentityInputs() {
        val packages =
            listOf(
                callerPackage("com.example.shared", 9, currentCertificate, historicalCertificate)
            )
        val targetObservation = UidPackageObservation(uid = 10_123, packages)
        val donorObservation = UidPackageObservation(uid = 20_456, packages)

        val targetIdentity = canonicalizer.canonicalize(targetObservation.packages)
        val donorIdentity = canonicalizer.canonicalize(donorObservation.packages)

        assertNotEquals(targetObservation.uid, donorObservation.uid)
        assertEquals(targetIdentity, donorIdentity)
    }

    @Test
    fun packageNameAndVersionChangeOnlyTheApplicationIdDigest() {
        val original =
            canonicalizer.canonicalize(
                listOf(callerPackage("com.example.app", 7, currentCertificate))
            )
        val renamed =
            canonicalizer.canonicalize(
                listOf(callerPackage("com.example.renamed", 7, currentCertificate))
            )
        val upgraded =
            canonicalizer.canonicalize(
                listOf(callerPackage("com.example.app", 8, currentCertificate))
            )

        listOf(renamed, upgraded).forEach { changed ->
            assertEquals(
                original.wireIdentity.signingCertificateDigest,
                changed.wireIdentity.signingCertificateDigest,
            )
            assertNotEquals(
                original.wireIdentity.attestationApplicationIdDigest,
                changed.wireIdentity.attestationApplicationIdDigest,
            )
            assertTrue(
                !original.attestationApplicationIdDer.contentEquals(
                    changed.attestationApplicationIdDer
                )
            )
        }
    }

    @Test
    fun signerChangeAltersSignerAggregateAndApplicationIdDigest() {
        val original =
            canonicalizer.canonicalize(
                listOf(callerPackage("com.example.app", 7, currentCertificate))
            )
        val resigned =
            canonicalizer.canonicalize(
                listOf(callerPackage("com.example.app", 7, historicalCertificate))
            )

        assertNotEquals(
            original.wireIdentity.signingCertificateDigest,
            resigned.wireIdentity.signingCertificateDigest,
        )
        assertNotEquals(
            original.wireIdentity.attestationApplicationIdDigest,
            resigned.wireIdentity.attestationApplicationIdDigest,
        )
    }

    @Test
    fun byteBackedInputsAndOutputsUseDefensiveCopiesAndContentEquality() {
        val certificate = currentCertificate.copyOf()
        val packageIdentity = callerPackage("com.example.app", 7, certificate)
        val equalPackage = callerPackage("com.example.app", 7, currentCertificate.copyOf())
        val identity = canonicalizer.canonicalize(listOf(packageIdentity))
        val equalIdentity =
            CanonicalCallerIdentity(identity.attestationApplicationIdDer, identity.wireIdentity)
        val expectedCertificate = currentCertificate.copyOf()
        val expectedDer = identity.attestationApplicationIdDer

        certificate.fill(0)
        packageIdentity.signingCertificateHistory.single().fill(0)
        identity.attestationApplicationIdDer.fill(0)

        assertEquals(equalPackage, packageIdentity)
        assertEquals(equalPackage.hashCode(), packageIdentity.hashCode())
        assertContentEquals(expectedCertificate, packageIdentity.signingCertificateHistory.single())
        assertEquals(equalIdentity, identity)
        assertEquals(equalIdentity.hashCode(), identity.hashCode())
        assertContentEquals(expectedDer, identity.attestationApplicationIdDer)
    }

    @Test
    fun rejectsMissingOrOutOfBoundsCanonicalIdentityData() {
        assertFailsWith<IllegalArgumentException> { canonicalizer.canonicalize(emptyList()) }
        assertFailsWith<IllegalArgumentException> { callerPackage("", 1, currentCertificate) }
        assertFailsWith<IllegalArgumentException> {
            callerPackage(
                "a".repeat(CallerPackageIdentity.MAX_PACKAGE_NAME_UTF8_BYTES + 1),
                1,
                currentCertificate,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            callerPackage("com.example.app", -1, currentCertificate)
        }
        assertFailsWith<IllegalArgumentException> {
            CallerPackageIdentity("com.example.app", 1, emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            callerPackage("com.example.app", 1, byteArrayOf())
        }
        assertFailsWith<IllegalArgumentException> {
            callerPackage(
                "com.example.app",
                1,
                ByteArray(CallerPackageIdentity.MAX_SIGNING_CERTIFICATE_BYTES + 1),
            )
        }
    }

    private fun callerPackage(
        packageName: String,
        longVersionCode: Long,
        vararg signingCertificateHistory: ByteArray,
    ) = CallerPackageIdentity(packageName, longVersionCode, signingCertificateHistory.asList())

    private fun String.hexBytes(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private data class UidPackageObservation(
        val uid: Int,
        val packages: List<CallerPackageIdentity>,
    )

    private companion object {
        val LOWERCASE_SHA_256 = Regex("[0-9a-f]{64}")
    }
}
