package org.matrix.teesimulator.twophone

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PublicProfileMutationTest {
    private val fixture = PublicProfileTestFixture()
    private val target by lazy { PublicProfileCodec.encodeTarget(fixture.targetProfile()) }
    private val donor by lazy { PublicProfileCodec.encodeDonor(fixture.donorProfile()) }

    @Test
    fun envelopeMutationsReturnDistinctTypedErrors() {
        assertFailsWith<PublicProfileException.InvalidMagic> {
            PublicProfileCodec.decodeTarget(target.mutatingInt(0, 0), fixture.fixtureIdentity)
        }
        assertFailsWith<PublicProfileException.UnknownVersion> {
            PublicProfileCodec.decodeTarget(target.mutatingShort(4, 2), fixture.fixtureIdentity)
        }
        assertFailsWith<PublicProfileException.Truncated> {
            PublicProfileCodec.decodeTarget(target.copyOf(target.size - 1), fixture.fixtureIdentity)
        }
        assertFailsWith<PublicProfileException.DuplicateField> {
            PublicProfileCodec.decodeTarget(
                target + target.encodedField(PublicProfileField.FIXTURE_PACKAGE),
                fixture.fixtureIdentity,
            )
        }
        assertFailsWith<PublicProfileException.OversizedProfile> {
            PublicProfileCodec.decodeTarget(
                ByteArray(PublicProfileCodec.MAX_PROFILE_BYTES + 1),
                fixture.fixtureIdentity,
            )
        }
    }

    @Test
    fun everyTargetFieldLengthRejectsZeroAndOversizeExactly() {
        target.fieldOffsets().forEach { field ->
            val invalid =
                assertFailsWith<PublicProfileException.InvalidFieldLength> {
                    PublicProfileCodec.decodeTarget(
                        target.mutatingInt(field.lengthOffset, 0),
                        fixture.fixtureIdentity,
                    )
                }
            assertEquals(field.tag, invalid.field)

            val oversized =
                assertFailsWith<PublicProfileException.OversizedField> {
                    PublicProfileCodec.decodeTarget(
                        target.mutatingInt(field.lengthOffset, Int.MAX_VALUE),
                        fixture.fixtureIdentity,
                    )
                }
            assertEquals(field.tag, oversized.field)
        }
    }

    @Test
    fun everyTargetFieldIsRejectedWhenDuplicated() {
        target.fieldOffsets().forEach { field ->
            val error =
                assertFailsWith<PublicProfileException.DuplicateField> {
                    PublicProfileCodec.decodeTarget(
                        target + target.encodedField(field.tag),
                        fixture.fixtureIdentity,
                    )
                }
            assertEquals(field.tag, error.field)
        }
    }

    @Test
    fun signerPinAndCertificateMutationsHaveExactErrors() {
        assertFailsWith<PublicProfileException.IdentityMismatch> {
            PublicProfileCodec.decodeTarget(
                target.flippingFieldByte(PublicProfileField.FIXTURE_SIGNER),
                fixture.fixtureIdentity,
            )
        }
        assertFailsWith<PublicProfileException.PinMismatch> {
            PublicProfileCodec.decodeTarget(
                target.flippingFieldByte(PublicProfileField.DONOR_PIN),
                fixture.fixtureIdentity,
            )
        }
        assertFailsWith<PublicProfileException.InvalidCertificate> {
            PublicProfileCodec.decodeTarget(
                target.flippingFieldByte(PublicProfileField.TARGET_CERTIFICATE),
                fixture.fixtureIdentity,
            )
        }
        assertFailsWith<PublicProfileException.CertificateMismatch> {
            PublicProfileCodec.decodeDonor(
                donor.replacingField(
                    PublicProfileField.TARGET_CERTIFICATE,
                    fixture.otherTarget.certificate.encoded,
                )
            )
        }
        assertFailsWith<PublicProfileException.IdentityMismatch> {
            PublicProfileCodec.decodeDonor(
                donor.flippingFieldByte(PublicProfileField.PAIR_TARGET_PIN)
            )
        }
    }

    @Test
    fun reorderedAndUnknownFieldsAreNeverTolerated() {
        val fields = target.fieldOffsets()
        val first = target.encodedField(fields[0].tag)
        val second = target.encodedField(fields[1].tag)
        val reordered =
            target.copyOfRange(0, 6) +
                second +
                first +
                target.copyOfRange(fields[2].tagOffset, target.size)

        assertFailsWith<PublicProfileException.UnexpectedField> {
            PublicProfileCodec.decodeTarget(reordered, fixture.fixtureIdentity)
        }
        assertFailsWith<PublicProfileException.UnexpectedField> {
            PublicProfileCodec.decodeTarget(target + unknownField(), fixture.fixtureIdentity)
        }
    }
}

internal data class EncodedProfileField(
    val tag: Int,
    val tagOffset: Int,
    val lengthOffset: Int,
    val valueOffset: Int,
    val length: Int,
)

internal fun ByteArray.fieldOffsets(): List<EncodedProfileField> {
    val fields = mutableListOf<EncodedProfileField>()
    var offset = 6
    while (offset < size) {
        val tag = ByteBuffer.wrap(this, offset, 2).short.toInt() and 0xffff
        val length = ByteBuffer.wrap(this, offset + 2, 4).int
        fields += EncodedProfileField(tag, offset, offset + 2, offset + 6, length)
        offset += 6 + length
    }
    return fields
}

internal fun ByteArray.encodedField(tag: Int): ByteArray {
    val field = fieldOffsets().single { it.tag == tag }
    return copyOfRange(field.tagOffset, field.valueOffset + field.length)
}

internal fun ByteArray.replacingField(tag: Int, replacement: ByteArray): ByteArray {
    val field = fieldOffsets().single { it.tag == tag }
    val encoded =
        ByteBuffer.allocate(6 + replacement.size)
            .putShort(tag.toShort())
            .putInt(replacement.size)
            .put(replacement)
            .array()
    return copyOfRange(0, field.tagOffset) +
        encoded +
        copyOfRange(field.valueOffset + field.length, size)
}

internal fun ByteArray.flippingFieldByte(tag: Int): ByteArray {
    val field = fieldOffsets().single { it.tag == tag }
    return copyOf().also { it[field.valueOffset] = (it[field.valueOffset].toInt() xor 1).toByte() }
}

internal fun ByteArray.mutatingInt(offset: Int, value: Int): ByteArray =
    copyOf().also { ByteBuffer.wrap(it).putInt(offset, value) }

internal fun ByteArray.mutatingShort(offset: Int, value: Int): ByteArray =
    copyOf().also { ByteBuffer.wrap(it).putShort(offset, value.toShort()) }

internal fun intBytes(value: Int): ByteArray = ByteBuffer.allocate(4).putInt(value).array()

private fun unknownField(): ByteArray =
    ByteBuffer.allocate(7).putShort(0x7fff.toShort()).putInt(1).put(1).array()
