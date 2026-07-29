package org.matrix.TEESimulator.twophone

import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.system.keystore2.IKeystoreService
import java.lang.reflect.Proxy
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.Keystore2Interceptor
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfileSource
import org.matrix.teesimulator.twophone.SpkiPin

class AndroidKeyStoreTargetTlsClientIdentityTest {
    private val pki = TargetTlsTestPki()
    private val root = pki.root("target-identity-root")
    private val identity = pki.client("target-identity", root)

    @Test
    fun openRequiresUidZeroTrustedEnvironmentAndNonExportableEcKey() {
        val valid = backend()
        val opened =
            AndroidKeyStoreTargetTlsClientIdentity.openExisting(
                SpkiPin.from(identity.certificate),
                Instant.now(),
                valid,
            )

        assertEquals("teesim_target_tls_client_v1", opened.alias)
        assertEquals(1, valid.signatures.get())
        assertNull(valid.key.encoded)

        listOf(
                backend(ownerUid = 1000),
                backend(level = TargetTlsSecurityLevel.SOFTWARE),
                backend(key = ExportablePrivateKey(identity.keyPair.private)),
                backend(key = NonExportablePrivateKey("RSA")),
            )
            .forEach { rejected ->
                assertFailsWith<TargetTlsClientIdentityException.InvalidKey> {
                    AndroidKeyStoreTargetTlsClientIdentity.openExisting(
                        SpkiPin.from(identity.certificate),
                        Instant.now(),
                        rejected,
                    )
                }
            }
    }

    @Test
    fun tlsKeySignatureWithRegisteredHookTakesUidZeroPlatformPathWithoutRecursion() {
        val profileReads = AtomicInteger()
        Keystore2Interceptor.installApprovedFixtureProfileSource(
            ApprovedFixtureProfileSource {
                profileReads.incrementAndGet()
                error("UID 0 TLS signing must not enter fixture routing")
            }
        )
        val backend = backend(hookEachSignature = true)

        try {
            withLegacyKeystoreRouteEnabledForRoot {
                AndroidKeyStoreTargetTlsClientIdentity.openExisting(
                    SpkiPin.from(identity.certificate),
                    Instant.now(),
                    backend,
                )
            }
        } finally {
            Keystore2Interceptor.installApprovedFixtureProfileSource(
                ApprovedFixtureProfileSource { null }
            )
        }

        assertEquals(1, backend.signatures.get())
        assertEquals(0, profileReads.get())
        assertEquals(1, backend.platformContinuations.get())
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> withLegacyKeystoreRouteEnabledForRoot(block: () -> T): T {
        val modesField =
            ConfigurationManager::class.java.getDeclaredField("packageModes").apply {
                isAccessible = true
            }
        val cacheField =
            ConfigurationManager::class.java.getDeclaredField("uidToPackagesCache").apply {
                isAccessible = true
            }
        val previousModes =
            modesField.get(ConfigurationManager) as Map<String, ConfigurationManager.Mode>
        val packageCache =
            cacheField.get(ConfigurationManager) as ConcurrentHashMap<Int, Array<String>>
        val previousRootPackages = packageCache[ROOT_UID]
        modesField.set(
            ConfigurationManager,
            previousModes + (ROOT_TEST_PACKAGE to ConfigurationManager.Mode.PATCH),
        )
        packageCache[ROOT_UID] = arrayOf(ROOT_TEST_PACKAGE)
        assertEquals(false, ConfigurationManager.shouldSkipUid(ROOT_UID))
        return try {
            block()
        } finally {
            modesField.set(ConfigurationManager, previousModes)
            if (previousRootPackages == null) packageCache.remove(ROOT_UID)
            else packageCache[ROOT_UID] = previousRootPackages
        }
    }

    private fun backend(
        ownerUid: Int = 0,
        level: TargetTlsSecurityLevel = TargetTlsSecurityLevel.TRUSTED_ENVIRONMENT,
        key: PrivateKey = NonExportablePrivateKey(),
        hookEachSignature: Boolean = false,
    ) =
        FakeTargetIdentityBackend(
            ownerUid,
            level,
            key,
            identity,
            pki.keyStore("provider-target", identity),
            hookEachSignature,
        )

    private companion object {
        const val ROOT_UID = 0
        const val ROOT_TEST_PACKAGE = "org.matrix.teesimulator.target.tls"
    }
}

private class FakeTargetIdentityBackend(
    private val ownerUid: Int,
    private val level: TargetTlsSecurityLevel,
    val key: PrivateKey,
    private val identity: TargetTlsTestIdentity,
    private val keyStore: KeyStore,
    private val hookEachSignature: Boolean,
) : TargetTlsClientIdentityBackend {
    val signatures = AtomicInteger()
    val platformContinuations = AtomicInteger()

    override fun containsAlias(alias: String) = true

    override fun generate(alias: String, spec: TargetTlsClientGenerationSpec) = Unit

    override fun load(alias: String) =
        TargetTlsClientBackendMaterial(
            key,
            ownerUid,
            level,
            listOf(identity.certificate, identity.rootCertificate),
            keyStore,
            TargetTlsTestPki.PASSWORD,
        )

    override fun signProbe(privateKey: PrivateKey, input: ByteArray): ByteArray {
        if (hookEachSignature) {
            val transactionCode =
                InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "listEntries")
            check(transactionCode >= IBinder.FIRST_CALL_TRANSACTION) {
                "unexpected listEntries transaction code: $transactionCode"
            }
            val result =
                Keystore2Interceptor.onPreTransact(
                    1,
                    binderProxy(),
                    transactionCode,
                    0,
                    0,
                    Process.myPid() + 1,
                    uninitializedParcel(),
                )
            if (result === BinderInterceptor.TransactionResult.ContinueAndSkipPost) {
                platformContinuations.incrementAndGet()
            }
        }
        signatures.incrementAndGet()
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(identity.keyPair.private)
            update(input)
            sign()
        }
    }

    override fun verifyProbe(
        publicKey: PublicKey,
        input: ByteArray,
        signature: ByteArray,
    ): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(input)
            verify(signature)
        }

    override fun delete(alias: String) = Unit
}

private class NonExportablePrivateKey(private val algorithmName: String = "EC") : PrivateKey {
    override fun getAlgorithm() = algorithmName

    override fun getFormat(): String? = null

    override fun getEncoded(): ByteArray? = null
}

private class ExportablePrivateKey(private val delegate: PrivateKey) : PrivateKey {
    override fun getAlgorithm(): String = delegate.algorithm

    override fun getFormat(): String? = delegate.format

    override fun getEncoded(): ByteArray = delegate.encoded
}

private fun binderProxy(): IBinder =
    Proxy.newProxyInstance(IBinder::class.java.classLoader, arrayOf(IBinder::class.java)) {
        _,
        method,
        _ ->
        when (method.returnType) {
            Boolean::class.javaPrimitiveType -> false
            Int::class.javaPrimitiveType -> 0
            Long::class.javaPrimitiveType -> 0L
            else -> null
        }
    } as IBinder

private fun uninitializedParcel(): Parcel {
    val unsafeType = Class.forName("sun.misc.Unsafe")
    val field = unsafeType.getDeclaredField("theUnsafe").apply { isAccessible = true }
    val unsafe = field.get(null)
    return unsafeType
        .getMethod("allocateInstance", Class::class.java)
        .invoke(unsafe, Parcel::class.java) as Parcel
}
