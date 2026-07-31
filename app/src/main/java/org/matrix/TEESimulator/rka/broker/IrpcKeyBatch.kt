package org.matrix.TEESimulator.rka.broker

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec

internal class IrpcGeneratedKey(macedPublicKey: ByteArray, spkiDer: ByteArray, keyBlob: ByteArray) {
    private val macedPublicKey = macedPublicKey.copyOf()
    private val spkiDer = spkiDer.copyOf()
    private var keyBlob = keyBlob.copyOf()

    init {
        require(macedPublicKey.isNotEmpty())
        require(spkiDer.isNotEmpty())
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spkiDer))
        require(keyBlob.isNotEmpty())
    }

    internal fun copyMacedPublicKey(): ByteArray = macedPublicKey.copyOf()

    internal fun copySpkiDer(): ByteArray = spkiDer.copyOf()

    internal fun moveKeyBlob(): ByteArray = keyBlob.also { keyBlob = ByteArray(0) }

    internal fun wipe() = keyBlob.fill(0)

    override fun toString(): String = "IrpcGeneratedKey(redacted)"
}

internal data class IrpcResolvedIdentity(
    val descriptor: String,
    val serviceName: String,
    val componentName: String,
    val uniqueId: String,
    val version: Int,
) {
    init {
        require(descriptor == IrpcClient.IRPC_DESCRIPTOR)
        require(serviceName == IrpcClient.DEFAULT_TEE_SERVICE)
        require(componentName.isNotEmpty() && componentName.length <= 255)
        require(uniqueId.isNotEmpty() && uniqueId.length <= 255)
        require(version == IrpcClient.REQUIRED_VERSION)
    }
}

internal class BrokerKeyBlobOwner(private val onWipe: (ByteArray) -> Unit = {}) : AutoCloseable {
    private val blobs = mutableMapOf<String, ByteArray>()

    fun retain(handle: ByteArray, key: IrpcGeneratedKey) {
        val blob = key.moveKeyBlob()
        if (blobs.putIfAbsent(handle.hex(), blob) != null) {
            blob.fill(0)
            onWipe(blob)
            throw IllegalArgumentException("duplicate opaque handle")
        }
    }

    fun clear() {
        blobs.values.forEach { blob ->
            blob.fill(0)
            onWipe(blob)
        }
        blobs.clear()
    }

    fun isEmpty(): Boolean = blobs.isEmpty()

    override fun close() = clear()
}

class IrpcKeyBatch
internal constructor(
    internal val identity: IrpcResolvedIdentity,
    keys: List<IrpcGeneratedKey>,
    private val owner: BrokerKeyBlobOwner = BrokerKeyBlobOwner(),
) {
    private val keys = keys.toList()

    init {
        require(keys.size in 1..RkpKeyCount.MAX)
        val hashes =
            keys.map {
                sha256(it.copyMacedPublicKey()).joinToString("") { byte -> "%02x".format(byte) }
            }
        require(hashes.toSet().size == hashes.size) { "duplicate public key" }
        require(keys.map { sha256(it.copySpkiDer()).hex() }.distinct().size == keys.size)
    }

    fun publicKeys(): List<ByteArray> = keys.map(IrpcGeneratedKey::copyMacedPublicKey)

    fun spkiPublicKeys(): List<ByteArray> = keys.map(IrpcGeneratedKey::copySpkiDer)

    fun publicKeyHashes(): List<ByteArray> = publicKeys().map(::sha256)

    internal fun retain(handles: List<ByteArray>): BrokerKeyBlobOwner {
        require(handles.size == keys.size)
        return try {
            handles.zip(keys).forEach { (handle, key) -> owner.retain(handle, key) }
            owner
        } catch (failure: RuntimeException) {
            wipe()
            throw failure
        }
    }

    internal fun wipe() {
        keys.forEach(IrpcGeneratedKey::wipe)
        owner.clear()
    }

    override fun toString(): String = "IrpcKeyBatch(count=${keys.size})"

    private companion object {
        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

internal object MacedP256Spki {
    private val prefix =
        byteArrayOf(
            0x30,
            0x59,
            0x30,
            0x13,
            0x06,
            0x07,
            0x2a,
            0x86.toByte(),
            0x48,
            0xce.toByte(),
            0x3d,
            0x02,
            0x01,
            0x06,
            0x08,
            0x2a,
            0x86.toByte(),
            0x48,
            0xce.toByte(),
            0x3d,
            0x03,
            0x01,
            0x07,
            0x03,
            0x42,
            0x00,
            0x04,
        )

    fun decode(maced: ByteArray): ByteArray {
        val outer = CborCursor(maced)
        require(outer.arrayLength() == 4)
        outer.bytes()
        outer.skip()
        val coseKey = CborCursor(outer.bytes())
        outer.bytes()
        require(outer.exhausted())
        val entries = coseKey.mapLength()
        var x: ByteArray? = null
        var y: ByteArray? = null
        repeat(entries) {
            when (coseKey.integer()) {
                1L -> require(coseKey.integer() == 2L)
                3L -> require(coseKey.integer() == -7L)
                -1L -> require(coseKey.integer() == 1L)
                -2L -> x = coseKey.bytes()
                -3L -> y = coseKey.bytes()
                else -> coseKey.skip()
            }
        }
        require(coseKey.exhausted())
        val xValue = requireNotNull(x).also { require(it.size == 32) }
        val yValue = requireNotNull(y).also { require(it.size == 32) }
        return prefix + xValue + yValue
    }
}

private class CborCursor(private val input: ByteArray) {
    private var offset = 0

    fun arrayLength(): Int = length(4)

    fun mapLength(): Int = length(5)

    fun bytes(): ByteArray {
        val size = length(2)
        require(offset + size <= input.size)
        return input.copyOfRange(offset, offset + size).also { offset += size }
    }

    fun integer(): Long {
        val initial = unsigned()
        val major = initial ushr 5
        require(major == 0 || major == 1)
        val value = argument(initial and 31)
        return if (major == 0) value else -1L - value
    }

    fun skip() {
        val initial = unsigned()
        val major = initial ushr 5
        val value = argument(initial and 31)
        when (major) {
            0,
            1 -> Unit
            2,
            3 -> offset += value.toInt()
            4 -> repeat(value.toInt()) { skip() }
            5 ->
                repeat(value.toInt()) {
                    skip()
                    skip()
                }
            else -> throw IllegalArgumentException("unsupported CBOR")
        }
        require(offset <= input.size)
    }

    fun exhausted(): Boolean = offset == input.size

    private fun length(expectedMajor: Int): Int {
        val initial = unsigned()
        require(initial ushr 5 == expectedMajor)
        return argument(initial and 31).toInt()
    }

    private fun argument(additional: Int): Long =
        when (additional) {
            in 0..23 -> additional.toLong()
            24 -> unsigned().toLong()
            25 -> (unsigned().toLong() shl 8) or unsigned().toLong()
            else -> throw IllegalArgumentException("unbounded CBOR")
        }

    private fun unsigned(): Int {
        require(offset < input.size)
        return input[offset++].toInt() and 0xff
    }
}
