package org.matrix.TEESimulator.rka.journal

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.IrpcResolvedIdentity

data class RkpIrpcIdentity(
    val descriptor: String,
    val serviceName: String,
    val componentName: String,
    val uniqueId: String,
    val version: Int,
    val securityLevel: String = "TEE",
    val algorithm: String = "EC",
    val curve: String = "P256",
) {
    init {
        require(descriptor == IrpcClient.IRPC_DESCRIPTOR)
        require(serviceName == IrpcClient.DEFAULT_TEE_SERVICE)
        require(componentName.toByteArray(StandardCharsets.UTF_8).size in 1..255)
        require(uniqueId.toByteArray(StandardCharsets.UTF_8).size in 1..255)
        require(version == IrpcClient.REQUIRED_VERSION)
        require(securityLevel == "TEE" && algorithm == "EC" && curve == "P256")
    }

    internal fun hash(): ByteArray {
        val identity = ByteArrayOutputStream()
        identity.write(0xa6)
        writeUnsigned(identity, 0)
        writeUnsigned(identity, 3)
        writeUnsigned(identity, 1)
        writeUnsigned(identity, 1)
        writeUnsigned(identity, 2)
        writeText(identity, componentName)
        writeUnsigned(identity, 3)
        writeText(identity, uniqueId)
        writeUnsigned(identity, 4)
        writeUnsigned(identity, 1)
        writeUnsigned(identity, 5)
        writeUnsigned(identity, 20)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(IRPC_DOMAIN)
        return digest.digest(identity.toByteArray())
    }

    companion object {
        private val IRPC_DOMAIN = "TEESIM-RKA-V2/IRPC\u0000".toByteArray(StandardCharsets.US_ASCII)

        private fun writeUnsigned(output: ByteArrayOutputStream, value: Int) {
            require(value in 0..23)
            output.write(value)
        }

        private fun writeText(output: ByteArrayOutputStream, value: String) {
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            if (bytes.size < 24) {
                output.write(0x60 or bytes.size)
            } else {
                output.write(0x78)
                output.write(bytes.size)
            }
            output.write(bytes)
            bytes.fill(0)
        }

        internal fun from(resolved: IrpcResolvedIdentity): RkpIrpcIdentity =
            RkpIrpcIdentity(
                resolved.descriptor,
                resolved.serviceName,
                resolved.componentName,
                resolved.uniqueId,
                resolved.version,
            )
    }
}
