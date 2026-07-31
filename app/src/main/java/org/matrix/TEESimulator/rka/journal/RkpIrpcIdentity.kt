package org.matrix.TEESimulator.rka.journal

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
        require(componentName.isNotEmpty() && componentName.length <= 255)
        require(uniqueId.isNotEmpty() && uniqueId.length <= 255)
        require(version == IrpcClient.REQUIRED_VERSION)
        require(securityLevel == "TEE" && algorithm == "EC" && curve == "P256")
    }

    internal fun hash(): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(
                listOf(
                        descriptor,
                        serviceName,
                        componentName,
                        uniqueId,
                        version.toString(),
                        securityLevel,
                        algorithm,
                        curve,
                    )
                    .joinToString("\u0000", prefix = "RKA-IRPC-IDENTITY-v1\u0000")
                    .toByteArray()
            )

    companion object {
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
