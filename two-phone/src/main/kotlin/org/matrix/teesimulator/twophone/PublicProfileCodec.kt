package org.matrix.teesimulator.twophone

object PublicProfileCodec {
    const val MAX_PROFILE_BYTES = 1024 * 1024

    private const val TARGET_MAGIC = 0x54505031
    private const val DONOR_MAGIC = 0x44505031
    private val PACKAGE =
        spec(PublicProfileField.FIXTURE_PACKAGE, 1, PublicProfileBinary.MAX_PACKAGE_BYTES)
    private val VERSION_CODE = exact(PublicProfileField.FIXTURE_VERSION, 8)
    private val SIGNER =
        exact(PublicProfileField.FIXTURE_SIGNER, PublicProfileBinary.SIGNER_DIGEST_BYTES)
    private val DONOR_ENDPOINT = spec(PublicProfileField.DONOR_ENDPOINT, 7, 19)
    private val DONOR_CHAIN =
        spec(PublicProfileField.DONOR_TRUST_CHAIN, 12, PublicProfileBinary.MAX_CHAIN_BYTES)
    private val DONOR_PIN = exact(PublicProfileField.DONOR_PIN, PublicProfileBinary.PIN_BYTES)
    private val TARGET_ALIAS =
        spec(PublicProfileField.TARGET_ALIAS, 1, PublicProfileBinary.MAX_ALIAS_BYTES)
    private val TARGET_CERT =
        spec(PublicProfileField.TARGET_CERTIFICATE, 1, PublicProfileBinary.MAX_CERTIFICATE_BYTES)
    private val TARGET_PIN = exact(PublicProfileField.TARGET_PIN, PublicProfileBinary.PIN_BYTES)
    private val MAX_OPERATIONS = exact(PublicProfileField.MAX_OPERATIONS, 4)
    private val DEADLINE = exact(PublicProfileField.DEADLINE_SECONDS, 4)
    private val PAIR_TARGET_PIN =
        exact(PublicProfileField.PAIR_TARGET_PIN, PublicProfileBinary.PIN_BYTES)
    private val PAIR_DONOR_PIN =
        exact(PublicProfileField.PAIR_DONOR_PIN, PublicProfileBinary.PIN_BYTES)
    private val TARGET_CHAIN =
        spec(PublicProfileField.TARGET_TRUST_CHAIN, 12, PublicProfileBinary.MAX_CHAIN_BYTES)
    private val DONOR_ALIAS =
        spec(PublicProfileField.DONOR_ALIAS, 1, PublicProfileBinary.MAX_ALIAS_BYTES)
    private val DONOR_CERT =
        spec(PublicProfileField.DONOR_CERTIFICATE, 1, PublicProfileBinary.MAX_CERTIFICATE_BYTES)
    private val BIND_ENDPOINT = spec(PublicProfileField.BIND_ENDPOINT, 7, 19)

    fun encodeTarget(profile: TargetPublicProfile): ByteArray =
        PublicProfileBinary.encode(
            TARGET_MAGIC,
            listOf(
                PublicProfileField.FIXTURE_PACKAGE to
                    PublicProfileBinary.text(
                        PublicProfileField.FIXTURE_PACKAGE,
                        profile.fixtureIdentity.packageName,
                    ),
                PublicProfileField.FIXTURE_VERSION to
                    PublicProfileBinary.long(profile.fixtureIdentity.versionCode),
                PublicProfileField.FIXTURE_SIGNER to profile.fixtureIdentity.signerDigest,
                PublicProfileField.DONOR_ENDPOINT to
                    PublicProfileBinary.endpoint(profile.donorEndpoint),
                PublicProfileField.DONOR_TRUST_CHAIN to
                    PublicProfileBinary.chain(
                        PublicProfileField.DONOR_TRUST_CHAIN,
                        profile.donorTrustChainDer,
                    ),
                PublicProfileField.DONOR_PIN to PublicProfileBinary.pin(profile.donorPin),
                PublicProfileField.TARGET_ALIAS to
                    PublicProfileBinary.text(
                        PublicProfileField.TARGET_ALIAS,
                        profile.targetIdentity.alias,
                    ),
                PublicProfileField.TARGET_CERTIFICATE to profile.targetIdentity.certificateDer,
                PublicProfileField.TARGET_PIN to
                    PublicProfileBinary.pin(profile.targetIdentity.pin),
                PublicProfileField.MAX_OPERATIONS to PublicProfileBinary.int(profile.maxOperations),
                PublicProfileField.DEADLINE_SECONDS to
                    PublicProfileBinary.int(profile.deadlineSeconds),
            ),
        )

    fun decodeTarget(
        encoded: ByteArray,
        expectedFixtureIdentity: FixturePackageIdentity,
    ): TargetPublicProfile {
        val reader = PublicProfileBinary.reader(encoded, TARGET_MAGIC)
        val fixture =
            FixturePackageIdentity.create(
                decodeProfileText(PublicProfileField.FIXTURE_PACKAGE, reader.read(PACKAGE)),
                decodeProfileLong(reader.read(VERSION_CODE)),
                reader.read(SIGNER),
            )
        val endpoint = decodeProfileEndpoint(reader.read(DONOR_ENDPOINT))
        val chain =
            decodeProfileChain(PublicProfileField.DONOR_TRUST_CHAIN, reader.read(DONOR_CHAIN))
        val donorPin = decodeProfilePin(reader.read(DONOR_PIN))
        val targetIdentity =
            ProvisionedTargetIdentity.create(
                decodeProfileText(PublicProfileField.TARGET_ALIAS, reader.read(TARGET_ALIAS)),
                reader.read(TARGET_CERT),
                decodeProfilePin(reader.read(TARGET_PIN)),
            )
        requireBounds(reader)
        reader.finish()
        return TargetPublicProfile.decoded(
            fixture,
            expectedFixtureIdentity,
            endpoint,
            chain,
            donorPin,
            targetIdentity,
        )
    }

    fun decodeTargetFixtureIdentity(encoded: ByteArray): FixturePackageIdentity {
        val reader = PublicProfileBinary.reader(encoded, TARGET_MAGIC)
        val fixture =
            FixturePackageIdentity.create(
                decodeProfileText(PublicProfileField.FIXTURE_PACKAGE, reader.read(PACKAGE)),
                decodeProfileLong(reader.read(VERSION_CODE)),
                reader.read(SIGNER),
            )
        decodeProfileEndpoint(reader.read(DONOR_ENDPOINT))
        decodeProfileChain(PublicProfileField.DONOR_TRUST_CHAIN, reader.read(DONOR_CHAIN))
        decodeProfilePin(reader.read(DONOR_PIN))
        ProvisionedTargetIdentity.create(
            decodeProfileText(PublicProfileField.TARGET_ALIAS, reader.read(TARGET_ALIAS)),
            reader.read(TARGET_CERT),
            decodeProfilePin(reader.read(TARGET_PIN)),
        )
        requireBounds(reader)
        reader.finish()
        return fixture
    }

    fun encodeDonor(profile: DonorPublicProfile): ByteArray =
        PublicProfileBinary.encode(
            DONOR_MAGIC,
            listOf(
                PublicProfileField.PAIR_TARGET_PIN to PublicProfileBinary.pin(profile.targetPin),
                PublicProfileField.PAIR_DONOR_PIN to
                    PublicProfileBinary.pin(profile.donorIdentity.pin),
                PublicProfileField.TARGET_CERTIFICATE to profile.targetIdentityCertificateDer,
                PublicProfileField.TARGET_TRUST_CHAIN to
                    PublicProfileBinary.chain(
                        PublicProfileField.TARGET_TRUST_CHAIN,
                        profile.targetTrustChainDer,
                    ),
                PublicProfileField.TARGET_PIN to PublicProfileBinary.pin(profile.targetPin),
                PublicProfileField.DONOR_ALIAS to
                    PublicProfileBinary.text(
                        PublicProfileField.DONOR_ALIAS,
                        profile.donorIdentity.alias,
                    ),
                PublicProfileField.DONOR_CERTIFICATE to profile.donorIdentity.certificateDer,
                PublicProfileField.DONOR_PIN to PublicProfileBinary.pin(profile.donorIdentity.pin),
                PublicProfileField.BIND_ENDPOINT to
                    PublicProfileBinary.endpoint(profile.bindEndpoint),
                PublicProfileField.MAX_OPERATIONS to PublicProfileBinary.int(profile.maxOperations),
                PublicProfileField.DEADLINE_SECONDS to
                    PublicProfileBinary.int(profile.deadlineSeconds),
            ),
        )

    fun decodeDonor(encoded: ByteArray): DonorPublicProfile {
        val reader = PublicProfileBinary.reader(encoded, DONOR_MAGIC)
        val pairTargetPin = decodeProfilePin(reader.read(PAIR_TARGET_PIN))
        val pairDonorPin = decodeProfilePin(reader.read(PAIR_DONOR_PIN))
        val targetCertificate = reader.read(TARGET_CERT)
        val targetChain =
            decodeProfileChain(PublicProfileField.TARGET_TRUST_CHAIN, reader.read(TARGET_CHAIN))
        val targetPin = decodeProfilePin(reader.read(TARGET_PIN))
        val donorIdentity =
            ProvisionedDonorIdentity.create(
                decodeProfileText(PublicProfileField.DONOR_ALIAS, reader.read(DONOR_ALIAS)),
                reader.read(DONOR_CERT),
                decodeProfilePin(reader.read(DONOR_PIN)),
            )
        val endpoint = decodeProfileEndpoint(reader.read(BIND_ENDPOINT))
        requireBounds(reader)
        reader.finish()
        return DonorPublicProfile.decoded(
            pairTargetPin,
            pairDonorPin,
            targetCertificate,
            targetChain,
            targetPin,
            donorIdentity,
            endpoint,
        )
    }

    private fun requireBounds(reader: PublicProfileReader) {
        val maxOperations = decodeProfileInt(reader.read(MAX_OPERATIONS))
        val deadlineSeconds = decodeProfileInt(reader.read(DEADLINE))
        if (
            maxOperations != PublicProfileLimits.MAX_OPERATIONS ||
                deadlineSeconds != PublicProfileLimits.DEADLINE_SECONDS
        ) {
            throw PublicProfileException.InvalidBounds()
        }
    }

    private fun spec(tag: Int, minimum: Int, maximum: Int) =
        PublicProfileFieldSpec(tag, minimum, maximum)

    private fun exact(tag: Int, size: Int) = PublicProfileFieldSpec(tag, size, size, size)
}
