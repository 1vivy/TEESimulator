package org.matrix.teesimulator.twophone

import java.security.MessageDigest

class TargetPublicProfile
private constructor(
    val fixtureIdentity: FixturePackageIdentity,
    val donorEndpoint: ProfileEndpoint,
    donorTrustChainDer: List<ByteArray>,
    val donorPin: PublicProfilePin,
    val targetIdentity: ProvisionedTargetIdentity,
) {
    val version = PublicProfileVersion.V1
    private val stableDonorTrustChainDer = donorTrustChainDer.map(ByteArray::copyOf)
    val maxOperations = PublicProfileLimits.MAX_OPERATIONS
    val deadlineSeconds = PublicProfileLimits.DEADLINE_SECONDS

    val donorTrustChainDer: List<ByteArray>
        get() = stableDonorTrustChainDer.map(ByteArray::copyOf)

    val pairIdentity: PairIdentity
        get() = PairIdentity(targetIdentity.pin.toString(), donorPin.toString())

    companion object {
        fun create(
            fixtureIdentity: FixturePackageIdentity,
            donorEndpoint: ProfileEndpoint,
            donorTrustChainDer: List<ByteArray>,
            donorPin: PublicProfilePin,
            targetIdentity: ProvisionedTargetIdentity,
        ): TargetPublicProfile {
            val chain =
                validatePublicChain(PublicProfileField.DONOR_TRUST_CHAIN, donorTrustChainDer)
            requirePin(PublicProfileField.DONOR_PIN, donorPin, chain.first())
            return TargetPublicProfile(
                fixtureIdentity,
                donorEndpoint,
                chain,
                donorPin,
                targetIdentity,
            )
        }

        internal fun decoded(
            fixtureIdentity: FixturePackageIdentity,
            expectedFixtureIdentity: FixturePackageIdentity,
            donorEndpoint: ProfileEndpoint,
            donorTrustChainDer: List<ByteArray>,
            donorPin: PublicProfilePin,
            targetIdentity: ProvisionedTargetIdentity,
        ): TargetPublicProfile {
            if (fixtureIdentity != expectedFixtureIdentity) {
                throw PublicProfileException.IdentityMismatch(PublicProfileField.FIXTURE_SIGNER)
            }
            return create(
                fixtureIdentity,
                donorEndpoint,
                donorTrustChainDer,
                donorPin,
                targetIdentity,
            )
        }
    }
}

class DonorPublicProfile
private constructor(
    val pairIdentity: PairIdentity,
    targetIdentityCertificateDer: ByteArray,
    targetTrustChainDer: List<ByteArray>,
    val targetPin: PublicProfilePin,
    val donorIdentity: ProvisionedDonorIdentity,
    val bindEndpoint: ProfileEndpoint,
) {
    val version = PublicProfileVersion.V1
    private val stableTargetIdentityCertificateDer = targetIdentityCertificateDer.copyOf()
    private val stableTargetTrustChainDer = targetTrustChainDer.map(ByteArray::copyOf)
    val maxOperations = PublicProfileLimits.MAX_OPERATIONS
    val deadlineSeconds = PublicProfileLimits.DEADLINE_SECONDS

    val targetIdentityCertificateDer: ByteArray
        get() = stableTargetIdentityCertificateDer.copyOf()

    val targetTrustChainDer: List<ByteArray>
        get() = stableTargetTrustChainDer.map(ByteArray::copyOf)

    companion object {
        @JvmStatic
        fun create(
            targetProfile: TargetPublicProfile,
            targetTrustChainDer: List<ByteArray>,
            donorIdentity: ProvisionedDonorIdentity,
            bindEndpoint: ProfileEndpoint,
        ): DonorPublicProfile {
            val targetCertificate = targetProfile.targetIdentity.certificateDer
            val chain =
                validatePublicChain(
                    PublicProfileField.TARGET_TRUST_CHAIN,
                    targetTrustChainDer,
                    targetCertificate,
                )
            if (
                !MessageDigest.isEqual(
                    targetProfile.donorTrustChainDer.first(),
                    donorIdentity.certificateDer,
                )
            ) {
                throw PublicProfileException.CertificateMismatch(
                    PublicProfileField.DONOR_CERTIFICATE
                )
            }
            if (targetProfile.donorPin != donorIdentity.pin) {
                throw PublicProfileException.IdentityMismatch(PublicProfileField.PAIR_DONOR_PIN)
            }
            return DonorPublicProfile(
                targetProfile.pairIdentity,
                targetCertificate,
                chain,
                targetProfile.targetIdentity.pin,
                donorIdentity,
                bindEndpoint,
            )
        }

        internal fun decoded(
            pairTargetPin: PublicProfilePin,
            pairDonorPin: PublicProfilePin,
            targetCertificate: ByteArray,
            targetTrustChain: List<ByteArray>,
            targetPin: PublicProfilePin,
            donorIdentity: ProvisionedDonorIdentity,
            bindEndpoint: ProfileEndpoint,
        ): DonorPublicProfile {
            val chain =
                validatePublicChain(
                    PublicProfileField.TARGET_TRUST_CHAIN,
                    targetTrustChain,
                    targetCertificate,
                )
            requirePin(PublicProfileField.TARGET_PIN, targetPin, targetCertificate)
            if (pairTargetPin != targetPin) {
                throw PublicProfileException.IdentityMismatch(PublicProfileField.PAIR_TARGET_PIN)
            }
            if (pairDonorPin != donorIdentity.pin) {
                throw PublicProfileException.IdentityMismatch(PublicProfileField.PAIR_DONOR_PIN)
            }
            return DonorPublicProfile(
                PairIdentity(pairTargetPin.toString(), pairDonorPin.toString()),
                targetCertificate,
                chain,
                targetPin,
                donorIdentity,
                bindEndpoint,
            )
        }
    }
}
