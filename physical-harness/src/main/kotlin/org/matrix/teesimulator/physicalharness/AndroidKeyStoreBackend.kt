package org.matrix.teesimulator.physicalharness

internal enum class BackendSecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    UNKNOWN,
}

internal class BackendKeyMaterial(
    val securityLevel: BackendSecurityLevel,
    generatedPublicKey: ByteArray,
    certificateChain: List<ByteArray>,
) {
    private val generatedPublicKeyBytes = generatedPublicKey.copyOf()
    private val certificateBytes = certificateChain.map(ByteArray::copyOf)

    val generatedPublicKey: ByteArray
        get() = generatedPublicKeyBytes.copyOf()

    val certificateChain: List<ByteArray>
        get() = certificateBytes.map(ByteArray::copyOf)
}

internal interface BackendSignOperation {
    fun update(input: ByteArray)

    fun finish(input: ByteArray): ByteArray

    fun abort()
}

internal interface AndroidKeyStoreBackend {
    fun aliases(): Set<String>

    fun containsAlias(alias: String): Boolean

    fun generate(alias: String, challenge: ByteArray): BackendKeyMaterial

    fun metadata(alias: String): BackendKeyMaterial?

    fun delete(alias: String)

    fun begin(alias: String): BackendSignOperation
}
