package org.matrix.TEESimulator.rka.broker

import java.security.MessageDigest

internal class IrpcGeneratedKey(publicKey: ByteArray, keyBlob: ByteArray) {
    private val publicKey = publicKey.copyOf()
    private val keyBlob = keyBlob.copyOf()

    init {
        require(publicKey.isNotEmpty())
        require(keyBlob.isNotEmpty())
    }

    internal fun copyPublicKey(): ByteArray = publicKey.copyOf()

    internal fun copyKeyBlob(): ByteArray = keyBlob.copyOf()

    internal fun wipe() = keyBlob.fill(0)

    override fun toString(): String = "IrpcGeneratedKey(redacted)"
}

class IrpcKeyBatch internal constructor(keys: List<IrpcGeneratedKey>) {
    private val keys = keys.map { IrpcGeneratedKey(it.copyPublicKey(), it.copyKeyBlob()) }

    init {
        require(keys.size in 1..RkpKeyCount.MAX)
        val hashes =
            keys.map { sha256(it.copyPublicKey()).joinToString("") { byte -> "%02x".format(byte) } }
        require(hashes.toSet().size == hashes.size) { "duplicate public key" }
    }

    fun publicKeys(): List<ByteArray> = keys.map(IrpcGeneratedKey::copyPublicKey)

    fun publicKeyHashes(): List<ByteArray> = publicKeys().map(::sha256)

    internal fun opaqueKeys(): List<IrpcGeneratedKey> =
        keys.map { IrpcGeneratedKey(it.copyPublicKey(), it.copyKeyBlob()) }

    internal fun wipe() = keys.forEach(IrpcGeneratedKey::wipe)

    override fun toString(): String = "IrpcKeyBatch(count=${keys.size})"

    private companion object {
        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
