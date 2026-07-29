package org.matrix.teesimulator.physicalharness

import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import org.matrix.teesimulator.twophone.DonorPublicProfile
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.ProfileEndpoint
import org.matrix.teesimulator.twophone.ProvisionedDonorIdentity
import org.matrix.teesimulator.twophone.ProvisionedTargetIdentity
import org.matrix.teesimulator.twophone.PublicProfileAtomicFileFacade
import org.matrix.teesimulator.twophone.PublicProfileCodec
import org.matrix.teesimulator.twophone.PublicProfilePin
import org.matrix.teesimulator.twophone.TargetPublicProfile

internal class PublicProfileStoreFixture {
    private val tls = DonorProfileFixture()
    val fixtureIdentity =
        FixturePackageIdentity.create("fixture.runtime", 7L, profileStoreBytes(32, 41))
    private val targetIdentity =
        ProvisionedTargetIdentity.create(
            "target-tls-v1",
            tls.target.certificate.encoded,
            PublicProfilePin.fromCertificate(tls.target.certificate.encoded),
        )
    private val donorIdentity =
        ProvisionedDonorIdentity.create(
            AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS,
            tls.donor.certificate.encoded,
            PublicProfilePin.fromCertificate(tls.donor.certificate.encoded),
        )

    fun target(port: Int = 42_321): TargetPublicProfile =
        TargetPublicProfile.create(
            fixtureIdentity,
            ProfileEndpoint.create(profileStoreBytes(4, 1), port),
            listOf(tls.donor.certificate.encoded, tls.donorRoot.certificate.encoded),
            donorIdentity.pin,
            targetIdentity,
        )

    fun donor(target: TargetPublicProfile = target(), port: Int = 42_321): DonorPublicProfile =
        DonorPublicProfile.create(
            target,
            listOf(tls.target.certificate.encoded, tls.targetRoot.certificate.encoded),
            donorIdentity,
            ProfileEndpoint.create(profileStoreBytes(4, 1), port),
        )
}

internal class FakePublicProfileAtomicFileFacade(directory: File) : PublicProfileAtomicFileFacade {
    private val committed = File(directory, "committed")
    private val pending = File(directory, "pending")
    var failWrite = false
    var startedWrites = 0
    var preparedWrites = 0
    var finishedWrites = 0

    override fun isPresent(): Boolean = committed.exists()

    override fun openRead(): FileInputStream {
        if (!committed.exists()) throw FileNotFoundException()
        return FileInputStream(committed)
    }

    override fun startWrite(): FileOutputStream {
        startedWrites += 1
        return object : FileOutputStream(pending) {
            override fun write(bytes: ByteArray) {
                if (failWrite) {
                    super.write(bytes, 0, bytes.size / 2)
                    throw InterruptedProfileWrite()
                }
                super.write(bytes)
            }
        }
    }

    override fun prepareWrite(stream: FileOutputStream) {
        preparedWrites += 1
    }

    override fun finishWrite(stream: FileOutputStream) {
        stream.close()
        Files.move(pending.toPath(), committed.toPath(), StandardCopyOption.REPLACE_EXISTING)
        finishedWrites += 1
    }

    override fun failWrite(stream: FileOutputStream) {
        stream.close()
        pending.delete()
    }
}

internal class InterruptedProfileWrite : RuntimeException()

internal data class StoredField(
    val tag: Int,
    val tagOffset: Int,
    val lengthOffset: Int,
    val valueOffset: Int,
    val length: Int,
)

internal fun ByteArray.storedFields(): List<StoredField> {
    val fields = mutableListOf<StoredField>()
    var offset = 6
    while (offset < size) {
        val tag = ByteBuffer.wrap(this, offset, 2).short.toInt() and 0xffff
        val length = ByteBuffer.wrap(this, offset + 2, 4).int
        fields += StoredField(tag, offset, offset + 2, offset + 6, length)
        offset += 6 + length
    }
    return fields
}

internal fun ByteArray.storeMutatingInt(offset: Int, value: Int): ByteArray =
    copyOf().also { ByteBuffer.wrap(it).putInt(offset, value) }

internal fun ByteArray.storeMutatingShort(offset: Int, value: Int): ByteArray =
    copyOf().also { ByteBuffer.wrap(it).putShort(offset, value.toShort()) }

internal fun ByteArray.storeFlippingField(tag: Int): ByteArray {
    val field = storedFields().single { it.tag == tag }
    return copyOf().also { it[field.valueOffset] = (it[field.valueOffset].toInt() xor 1).toByte() }
}

internal fun ByteArray.storeDuplicateField(tag: Int): ByteArray {
    val field = storedFields().single { it.tag == tag }
    return this + copyOfRange(field.tagOffset, field.valueOffset + field.length)
}

internal fun profileStoreBytes(size: Int, seed: Int): ByteArray =
    ByteArray(size) { index -> (index + seed).toByte() }

internal fun PublicProfileStoreFixture.targetBytes(port: Int = 42_321): ByteArray =
    PublicProfileCodec.encodeTarget(target(port))

internal fun PublicProfileStoreFixture.donorBytes(port: Int = 42_321): ByteArray =
    PublicProfileCodec.encodeDonor(donor(port = port))
