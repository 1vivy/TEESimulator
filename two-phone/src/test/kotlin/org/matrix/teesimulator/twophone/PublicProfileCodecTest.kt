package org.matrix.teesimulator.twophone

import java.security.PrivateKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class PublicProfileCodecTest {
    private val fixture = PublicProfileTestFixture()

    @Test
    fun mutuallyConsistentProfilesRoundTripCanonically() {
        val target = fixture.targetProfile()
        val donor = fixture.donorProfile(target)

        val targetBytes = PublicProfileCodec.encodeTarget(target)
        val donorBytes = PublicProfileCodec.encodeDonor(donor)
        val decodedTarget = PublicProfileCodec.decodeTarget(targetBytes, fixture.fixtureIdentity)
        val decodedDonor = PublicProfileCodec.decodeDonor(donorBytes)

        assertEquals(target.pairIdentity, decodedTarget.pairIdentity)
        assertEquals(decodedTarget.pairIdentity, decodedDonor.pairIdentity)
        assertEquals(PublicProfileLimits.MAX_OPERATIONS, decodedTarget.maxOperations)
        assertEquals(PublicProfileLimits.DEADLINE_SECONDS, decodedDonor.deadlineSeconds)
        assertContentEquals(targetBytes, PublicProfileCodec.encodeTarget(decodedTarget))
        assertContentEquals(donorBytes, PublicProfileCodec.encodeDonor(decodedDonor))
    }

    @Test
    fun donorConstructionRequiresACompletedTargetProfile() {
        val create =
            DonorPublicProfile::class.java.declaredMethods.single {
                it.name == "create" && it.parameterTypes.size == 4
            }

        assertEquals(TargetPublicProfile::class.java, create.parameterTypes.first())
        assertFailsWith<PublicProfileException.CertificateMismatch> {
            fixture.donorProfile(
                donor =
                    ProvisionedDonorIdentity.create(
                        "other-donor",
                        fixture.otherDonor.certificate.encoded,
                        PublicProfilePin.fromCertificate(fixture.otherDonor.certificate.encoded),
                    )
            )
        }
    }

    @Test
    fun decodedPublicModelsHaveNoPrivateKeyFieldOfAnyKind() {
        val models =
            listOf(
                PublicProfileCodec.decodeTarget(
                    PublicProfileCodec.encodeTarget(fixture.targetProfile()),
                    fixture.fixtureIdentity,
                ),
                PublicProfileCodec.decodeDonor(
                    PublicProfileCodec.encodeDonor(fixture.donorProfile())
                ),
            )

        models.flatMap(::modelGraph).forEach { model ->
            model.javaClass.declaredFields.forEach { field ->
                val name = field.name.lowercase()
                assertFalse(
                    name.contains("privatekey") ||
                        name.contains("password") ||
                        name.contains("secret")
                )
                assertFalse(PrivateKey::class.java.isAssignableFrom(field.type))
            }
        }
    }

    @Test
    fun boundsAreFixedAndCannotBeEncodedOrDecodedDifferently() {
        val target = PublicProfileCodec.encodeTarget(fixture.targetProfile())

        assertFailsWith<PublicProfileException.InvalidBounds> {
            PublicProfileCodec.decodeTarget(
                target.replacingField(PublicProfileField.MAX_OPERATIONS, intBytes(2)),
                fixture.fixtureIdentity,
            )
        }
        assertFailsWith<PublicProfileException.InvalidBounds> {
            PublicProfileCodec.decodeTarget(
                target.replacingField(PublicProfileField.DEADLINE_SECONDS, intBytes(121)),
                fixture.fixtureIdentity,
            )
        }
    }

    @Test
    fun targetProfileExposesItsFixtureIdentityForFailClosedBootstrap() {
        val target = fixture.targetProfile()

        val decoded =
            PublicProfileCodec.decodeTargetFixtureIdentity(PublicProfileCodec.encodeTarget(target))

        assertEquals(target.fixtureIdentity, decoded)
    }

    private fun modelGraph(root: Any): List<Any> {
        val nested =
            when (root) {
                is TargetPublicProfile -> listOf(root.fixtureIdentity, root.targetIdentity)
                is DonorPublicProfile -> listOf(root.donorIdentity)
                else -> emptyList()
            }
        return listOf(root) + nested
    }
}
