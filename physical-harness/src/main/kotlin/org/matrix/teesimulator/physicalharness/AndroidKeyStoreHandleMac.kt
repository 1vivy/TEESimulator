package org.matrix.teesimulator.physicalharness

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.Key
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

sealed class AndroidKeyStoreHandleMacException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class AliasAlreadyExists :
        AndroidKeyStoreHandleMacException("handle authenticator key already exists")

    class KeyNotFound : AndroidKeyStoreHandleMacException("handle authenticator key not found")

    class WrongKeyType : AndroidKeyStoreHandleMacException("invalid handle authenticator key type")

    class ExportableKey :
        AndroidKeyStoreHandleMacException("handle authenticator key is exportable")

    class UntrustedSecurityLevel :
        AndroidKeyStoreHandleMacException("untrusted handle authenticator security level")

    class BackendFailure(cause: Throwable) :
        AndroidKeyStoreHandleMacException("AndroidKeyStore handle MAC operation failed", cause)
}

class AndroidKeyStoreHandleMac
private constructor(
    private val secretKey: SecretKey,
    private val backend: AndroidKeyStoreHandleMacBackend,
    private var rollbackAllowed: Boolean,
) : HandleMac {
    override fun sign(input: ByteArray): ByteArray = backend.sign(secretKey, input.copyOf())

    internal fun deleteForBootstrapRollback() {
        synchronized(bootstrapLock) {
            check(rollbackAllowed) { "authenticator rollback is not allowed" }
            backend.delete(KEY_ALIAS)
            rollbackAllowed = false
        }
    }

    companion object {
        const val KEY_ALIAS = "teesim_state_mac_v1"

        private const val MAC_ALGORITHM = "HmacSHA256"
        private val bootstrapLock = Any()

        fun exists(): Boolean = exists(PlatformAndroidKeyStoreHandleMacBackend())

        fun createNew(): AndroidKeyStoreHandleMac =
            createNew(PlatformAndroidKeyStoreHandleMacBackend())

        fun openExisting(): AndroidKeyStoreHandleMac =
            openExisting(PlatformAndroidKeyStoreHandleMacBackend())

        internal fun exists(backend: AndroidKeyStoreHandleMacBackend): Boolean =
            synchronized(bootstrapLock) { backend.containsAlias(KEY_ALIAS) }

        internal fun createNew(backend: AndroidKeyStoreHandleMacBackend): AndroidKeyStoreHandleMac =
            synchronized(bootstrapLock) {
                if (backend.containsAlias(KEY_ALIAS)) {
                    throw AndroidKeyStoreHandleMacException.AliasAlreadyExists()
                }
                backend.generate(KEY_ALIAS)
                try {
                    loadValidated(backend, rollbackAllowed = true)
                } catch (failure: RuntimeException) {
                    cleanupRejectedKey(backend, failure)
                }
            }

        internal fun openExisting(
            backend: AndroidKeyStoreHandleMacBackend
        ): AndroidKeyStoreHandleMac =
            synchronized(bootstrapLock) {
                if (!backend.containsAlias(KEY_ALIAS)) {
                    throw AndroidKeyStoreHandleMacException.KeyNotFound()
                }
                loadValidated(backend, rollbackAllowed = false)
            }

        private fun loadValidated(
            backend: AndroidKeyStoreHandleMacBackend,
            rollbackAllowed: Boolean,
        ): AndroidKeyStoreHandleMac {
            val key =
                backend.load(KEY_ALIAS) ?: throw AndroidKeyStoreHandleMacException.KeyNotFound()
            val secretKey =
                key as? SecretKey ?: throw AndroidKeyStoreHandleMacException.WrongKeyType()
            if (!secretKey.algorithm.equals(MAC_ALGORITHM, ignoreCase = true)) {
                throw AndroidKeyStoreHandleMacException.WrongKeyType()
            }
            if (secretKey.encoded != null) {
                throw AndroidKeyStoreHandleMacException.ExportableKey()
            }
            if (backend.securityLevel(secretKey) != BackendSecurityLevel.TRUSTED_ENVIRONMENT) {
                throw AndroidKeyStoreHandleMacException.UntrustedSecurityLevel()
            }
            return AndroidKeyStoreHandleMac(secretKey, backend, rollbackAllowed)
        }

        private fun cleanupRejectedKey(
            backend: AndroidKeyStoreHandleMacBackend,
            failure: RuntimeException,
        ): Nothing {
            try {
                backend.delete(KEY_ALIAS)
            } catch (cleanupFailure: RuntimeException) {
                failure.addSuppressed(cleanupFailure)
            }
            throw failure
        }
    }
}

internal interface AndroidKeyStoreHandleMacBackend {
    fun containsAlias(alias: String): Boolean

    fun generate(alias: String)

    fun load(alias: String): Key?

    fun securityLevel(secretKey: SecretKey): BackendSecurityLevel

    fun sign(secretKey: SecretKey, input: ByteArray): ByteArray

    fun delete(alias: String)
}

private class PlatformAndroidKeyStoreHandleMacBackend : AndroidKeyStoreHandleMacBackend {
    override fun containsAlias(alias: String): Boolean = handleMacPlatformCall {
        loadKeyStore().containsAlias(alias)
    }

    override fun generate(alias: String) {
        handleMacPlatformCall {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEY_STORE)
                .apply {
                    init(
                        KeyGenParameterSpec.Builder(
                                alias,
                                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                            )
                            .setKeySize(HMAC_KEY_SIZE_BITS)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setUserAuthenticationRequired(false)
                            .setIsStrongBoxBacked(false)
                            .build()
                    )
                }
                .generateKey()
        }
    }

    override fun load(alias: String): Key? = handleMacPlatformCall {
        loadKeyStore().getKey(alias, null)
    }

    override fun securityLevel(secretKey: SecretKey): BackendSecurityLevel = handleMacPlatformCall {
        val keyInfo =
            SecretKeyFactory.getInstance(secretKey.algorithm, ANDROID_KEY_STORE)
                .getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
        keyInfo.securityLevel.toHandleMacSecurityLevel()
    }

    override fun sign(secretKey: SecretKey, input: ByteArray): ByteArray = handleMacPlatformCall {
        Mac.getInstance(MAC_ALGORITHM).apply { init(secretKey) }.doFinal(input)
    }

    override fun delete(alias: String) {
        handleMacPlatformCall { loadKeyStore().deleteEntry(alias) }
    }

    private fun loadKeyStore(): KeyStore = handleMacPlatformCall {
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
    }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val HMAC_KEY_SIZE_BITS = 256
        const val MAC_ALGORITHM = "HmacSHA256"
    }
}

private fun Int.toHandleMacSecurityLevel(): BackendSecurityLevel =
    when (this) {
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> BackendSecurityLevel.SOFTWARE
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> BackendSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> BackendSecurityLevel.STRONGBOX
        else -> BackendSecurityLevel.UNKNOWN
    }

private inline fun <T> handleMacPlatformCall(block: () -> T): T =
    try {
        block()
    } catch (exception: GeneralSecurityException) {
        throw AndroidKeyStoreHandleMacException.BackendFailure(exception)
    } catch (exception: IOException) {
        throw AndroidKeyStoreHandleMacException.BackendFailure(exception)
    } catch (exception: ProviderException) {
        throw AndroidKeyStoreHandleMacException.BackendFailure(exception)
    }
