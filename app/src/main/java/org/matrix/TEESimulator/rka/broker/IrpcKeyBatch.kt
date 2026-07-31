package org.matrix.TEESimulator.rka.broker

import java.security.MessageDigest

internal class IrpcGeneratedKey(publicKey: ByteArray, keyBlob: ByteArray) {
    private val publicKey = publicKey.copyOf()
    private var keyBlob = keyBlob.copyOf()

    init {
        require(publicKey.isNotEmpty())
        require(keyBlob.isNotEmpty())
    }

    internal fun copyPublicKey(): ByteArray = publicKey.copyOf()

    internal fun moveKeyBlob(): ByteArray = keyBlob.also { keyBlob = ByteArray(0) }

    internal fun wipe() = keyBlob.fill(0)

    override fun toString(): String = "IrpcGeneratedKey(redacted)"
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
    keys: List<IrpcGeneratedKey>,
    private val owner: BrokerKeyBlobOwner = BrokerKeyBlobOwner(),
) {
    private val keys = keys.toList()

    init {
        require(keys.size in 1..RkpKeyCount.MAX)
        val hashes =
            keys.map { sha256(it.copyPublicKey()).joinToString("") { byte -> "%02x".format(byte) } }
        require(hashes.toSet().size == hashes.size) { "duplicate public key" }
    }

    fun publicKeys(): List<ByteArray> = keys.map(IrpcGeneratedKey::copyPublicKey)

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
