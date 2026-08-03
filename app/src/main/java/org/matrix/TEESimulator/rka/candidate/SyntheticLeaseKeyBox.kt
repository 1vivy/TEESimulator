package org.matrix.TEESimulator.rka.candidate

import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import org.matrix.TEESimulator.pki.KeyBox

/** Root-owned, donor-certified attestation key selected from the current synthetic RKP lease. */
internal class SyntheticLeaseKeyBox(
    val epoch: Long,
    val validUntilMillis: Long,
    val keyBox: KeyBox,
    internal val profileIdHash: ByteArray,
    internal val peerSpkiHash: ByteArray,
) {
    override fun toString(): String =
        "SyntheticLeaseKeyBox(epoch=$epoch,validUntilMillis=$validUntilMillis,key=redacted)"
}

/** Production entry point. Every read revalidates the atomically replaced record. */
internal object SyntheticLeaseRegistry {
    private val store =
        FileSyntheticLeaseStore(Path.of("/data/adb/teesimulator-rka/synthetic-leases/state.bin"))

    fun current(nowMillis: Long = System.currentTimeMillis()): SyntheticLeaseKeyBox =
        store.loadCurrent(nowMillis)
}

internal class FileSyntheticLeaseStore(
    private val path: Path,
    private val activationPath: Path =
        Path.of(
            "/data/adb/teesimulator-rka/records/" +
                "7061697265642d61637469766174696f6e2d7631"
        ),
) {
    fun loadCurrent(nowMillis: Long): SyntheticLeaseKeyBox {
        val encoded = readSecureRecord(path, MAX_STATE_BYTES)
        val activation = readSecureRecord(activationPath, ACTIVATION_BYTES)
        return try {
            SyntheticLeaseCodec.decodeCurrent(encoded, nowMillis).also {
                SyntheticLeaseActivationCodec.requireMatch(
                    activation,
                    it.profileIdHash,
                    it.peerSpkiHash,
                )
            }
        } finally {
            encoded.fill(0)
            activation.fill(0)
        }
    }

    private fun readSecureRecord(target: Path, maximum: Int): ByteArray {
        requireSecureDirectory(requireNotNull(target.parent?.parent))
        requireSecureDirectory(requireNotNull(target.parent))
        val descriptor =
            Os.open(
                target.toString(),
                OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                0,
            )
        try {
            val before = LeaseFileSignature.from(Os.fstat(descriptor))
            val namedBefore = LeaseFileSignature.from(Os.lstat(target.toString()))
            require(before == namedBefore)
            require(before.regular && before.uid == 0 && before.gid == 0 && before.mode == 0x180)
            require(before.size in 1..maximum.toLong())
            val encoded = ByteArray(before.size.toInt())
            var offset = 0
            while (offset < encoded.size) {
                val read =
                    Os.pread(descriptor, encoded, offset, encoded.size - offset, offset.toLong())
                require(read > 0)
                offset += read
            }
            require(Os.pread(descriptor, ByteArray(1), 0, 1, encoded.size.toLong()) == 0)
            val after = LeaseFileSignature.from(Os.fstat(descriptor))
            val namedAfter = LeaseFileSignature.from(Os.lstat(target.toString()))
            require(after == before && namedAfter == before)
            return encoded
        } finally {
            Os.close(descriptor)
        }
    }

    private fun requireSecureDirectory(directory: Path) {
        val stat = Os.lstat(directory.toString())
        require(stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR)
        require(stat.st_uid == 0 && stat.st_gid == 0 && stat.st_mode and 0x1ff == 0x1c0)
    }
}

private data class LeaseFileSignature(
    val device: Long,
    val inode: Long,
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val size: Long,
    val modifiedSeconds: Long,
    val modifiedNanos: Long,
    val changedSeconds: Long,
    val changedNanos: Long,
    val regular: Boolean,
) {
    companion object {
        fun from(stat: StructStat): LeaseFileSignature =
            LeaseFileSignature(
                stat.st_dev,
                stat.st_ino,
                stat.st_uid,
                stat.st_gid,
                stat.st_mode and 0x1ff,
                stat.st_size,
                stat.st_mtim.tv_sec,
                stat.st_mtim.tv_nsec,
                stat.st_ctim.tv_sec,
                stat.st_ctim.tv_nsec,
                stat.st_mode and OsConstants.S_IFMT == OsConstants.S_IFREG,
            )
    }
}

/** Pure decoder shared by production and host-side unit tests. */
internal object SyntheticLeaseCodec {
    fun decodeCurrent(encoded: ByteArray, nowMillis: Long): SyntheticLeaseKeyBox {
        require(encoded.size in 1..MAX_STATE_BYTES)
        require(nowMillis >= 0)
        val cursor = LeaseCursor(encoded)
        require(cursor.bytes(MAGIC.size).contentEquals(MAGIC))
        val currentPresent = cursor.flag()
        val nextPresent = cursor.flag()
        require(currentPresent)
        val current = decodeBundle(cursor, nowMillis)
        val next = if (nextPresent) decodeBundle(cursor, nowMillis) else null
        cursor.finish()
        if (next != null) {
            require(current.epoch != Long.MAX_VALUE && next.epoch == current.epoch + 1)
            require(next.profileIdHash.contentEquals(current.profileIdHash))
            require(next.peerSpkiHash.contentEquals(current.peerSpkiHash))
        }
        return SyntheticLeaseKeyBox(
            current.epoch,
            current.validUntilMillis,
            current.keyBox,
            current.profileIdHash,
            current.peerSpkiHash,
        )
    }

    private fun decodeBundle(cursor: LeaseCursor, nowMillis: Long): DecodedBundle {
        val epoch = cursor.u64()
        val profileIdHash = cursor.bytes(HASH_BYTES)
        val peerSpkiHash = cursor.bytes(HASH_BYTES)
        val notBeforeMillis = cursor.u64()
        val notAfterMillis = cursor.u64()
        val storedLeaseId = cursor.bytes(HASH_BYTES)
        val privateKeyPkcs8 = cursor.u16Bytes(1, MAX_PKCS8_BYTES)
        val publicSpki = cursor.u16Bytes(1, MAX_CERTIFICATE_BYTES)
        val certificateCount = cursor.u8()
        require(certificateCount in 2..MAX_CERTIFICATES)
        var chainBytes = 0
        val encodedChain =
            List(certificateCount) {
                cursor.u32Bytes(1, MAX_CERTIFICATE_BYTES).also {
                    chainBytes = Math.addExact(chainBytes, it.size)
                    require(chainBytes <= MAX_CHAIN_BYTES)
                }
            }
        require(notAfterMillis > notBeforeMillis)
        require(nowMillis in notBeforeMillis until notAfterMillis)
        val leaseId =
            leaseId(
                epoch,
                profileIdHash,
                peerSpkiHash,
                notBeforeMillis,
                notAfterMillis,
                publicSpki,
                encodedChain,
            )
        require(leaseId.contentEquals(storedLeaseId))
        val privateKey =
            try {
                KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privateKeyPkcs8))
                    as? ECPrivateKey ?: error("synthetic lease private key is not EC")
            } finally {
                privateKeyPkcs8.fill(0)
            }
        require(privateKey.params.curve.field.fieldSize == 256)
        val certificates = encodedChain.map(::parseCertificate)
        val leaf = certificates.first()
        require(leaf.publicKey.encoded.contentEquals(publicSpki))
        require(leaf.basicConstraints >= 0)
        require(leaf.keyUsage?.getOrNull(KEY_CERT_SIGN_INDEX) == true)
        certificates.forEach { it.checkValidity(Date(nowMillis)) }
        require(notBeforeMillis >= leaf.notBefore.time)
        require(notAfterMillis <= leaf.notAfter.time)
        certificates.zipWithNext().forEach { (child, issuer) ->
            require(child.issuerX500Principal == issuer.subjectX500Principal)
            child.verify(issuer.publicKey)
        }
        val root = certificates.last()
        require(root.issuerX500Principal == root.subjectX500Principal)
        root.verify(root.publicKey)
        val proof =
            MessageDigest.getInstance("SHA-256").digest(SELF_CHECK_DOMAIN + leaseId + publicSpki)
        val signature =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(proof)
                sign()
            }
        require(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(leaf.publicKey)
                update(proof)
                verify(signature)
            }
        )
        proof.fill(0)
        signature.fill(0)
        return DecodedBundle(
            epoch,
            profileIdHash,
            peerSpkiHash,
            notAfterMillis,
            KeyBox(KeyPair(leaf.publicKey, privateKey), certificates),
        )
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate {
        val input = ByteArrayInputStream(encoded)
        val certificate =
            CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        require(input.available() == 0)
        require(certificate.encoded.contentEquals(encoded))
        return certificate
    }

    private fun leaseId(
        epoch: Long,
        profileIdHash: ByteArray,
        peerSpkiHash: ByteArray,
        notBeforeMillis: Long,
        notAfterMillis: Long,
        publicSpki: ByteArray,
        certificateChain: List<ByteArray>,
    ): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update(LEASE_ID_DOMAIN)
            update(longBytes(epoch))
            update(profileIdHash)
            update(peerSpkiHash)
            update(longBytes(notBeforeMillis))
            update(longBytes(notAfterMillis))
            update(longBytes(publicSpki.size.toLong()))
            update(publicSpki)
            certificateChain.forEach {
                update(longBytes(it.size.toLong()))
                update(it)
            }
            digest()
        }

    private fun longBytes(value: Long): ByteArray =
        ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array()
}

internal object SyntheticLeaseActivationCodec {
    fun requireMatch(
        encoded: ByteArray,
        expectedProfileIdHash: ByteArray,
        expectedPeerSpkiHash: ByteArray,
    ) {
        require(encoded.size == ACTIVATION_BYTES)
        require(encoded.copyOfRange(0, ACTIVATION_MAGIC.size).contentEquals(ACTIVATION_MAGIC))
        val peer =
            encoded.copyOfRange(ACTIVATION_MAGIC.size, ACTIVATION_MAGIC.size + HASH_BYTES)
        val profile =
            encoded.copyOfRange(
                ACTIVATION_MAGIC.size + HASH_BYTES,
                ACTIVATION_MAGIC.size + 2 * HASH_BYTES,
            )
        require(peer.contentEquals(expectedPeerSpkiHash))
        require(profile.contentEquals(expectedProfileIdHash))
    }
}

private data class DecodedBundle(
    val epoch: Long,
    val profileIdHash: ByteArray,
    val peerSpkiHash: ByteArray,
    val validUntilMillis: Long,
    val keyBox: KeyBox,
)

private class LeaseCursor(private val encoded: ByteArray) {
    private var offset = 0

    fun bytes(length: Int): ByteArray {
        require(length >= 0)
        val end = Math.addExact(offset, length)
        require(end <= encoded.size)
        return encoded.copyOfRange(offset, end).also { offset = end }
    }

    fun u8(): Int = bytes(1).single().toInt() and 0xff

    fun flag(): Boolean =
        when (val value = u8()) {
            0 -> false
            1 -> true
            else -> error("invalid synthetic lease flag $value")
        }

    fun u64(): Long =
        ByteBuffer.wrap(bytes(Long.SIZE_BYTES)).order(ByteOrder.BIG_ENDIAN).long.also {
            require(it >= 0)
        }

    fun u16Bytes(minimum: Int, maximum: Int): ByteArray {
        val length = ByteBuffer.wrap(bytes(2)).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xffff
        require(length in minimum..maximum)
        return bytes(length)
    }

    fun u32Bytes(minimum: Int, maximum: Int): ByteArray {
        val length =
            ByteBuffer.wrap(bytes(Int.SIZE_BYTES)).order(ByteOrder.BIG_ENDIAN).int.toLong() and
                0xffff_ffffL
        require(length in minimum.toLong()..maximum.toLong())
        return bytes(length.toInt())
    }

    fun finish() {
        require(offset == encoded.size)
    }
}

private const val MAX_STATE_BYTES = 1_048_576
private const val MAX_PKCS8_BYTES = 4_096
private const val MAX_CERTIFICATE_BYTES = 65_536
private const val MAX_CHAIN_BYTES = 524_288
private const val MAX_CERTIFICATES = 20
private const val HASH_BYTES = 32
private const val KEY_CERT_SIGN_INDEX = 5
private const val ACTIVATION_BYTES = 237
private val MAGIC =
    byteArrayOf('R'.code.toByte(), 'K'.code.toByte(), 'S'.code.toByte(), 'L'.code.toByte(), 1)
private val ACTIVATION_MAGIC =
    byteArrayOf('R'.code.toByte(), 'K'.code.toByte(), 'P'.code.toByte(), 'A'.code.toByte(), 1)
private val LEASE_ID_DOMAIN = "TEESimulator-RS synthetic lease id v1\u0000".toByteArray()
private val SELF_CHECK_DOMAIN = "TEESimulator-RS synthetic lease self-check v1\u0000".toByteArray()
