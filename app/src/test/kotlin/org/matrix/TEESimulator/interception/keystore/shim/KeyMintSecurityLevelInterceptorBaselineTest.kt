package org.matrix.TEESimulator.interception.keystore.shim

import android.content.pm.IPackageManager
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyEntryResponse
import java.lang.reflect.Proxy
import java.security.KeyPairGenerator
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfileSource
import org.matrix.TEESimulator.interception.policy.FixtureInterceptionPolicy
import org.matrix.TEESimulator.interception.policy.FixturePackageResolver
import org.matrix.TEESimulator.twophone.FakeOriginProcessDeathLease

class KeyMintSecurityLevelInterceptorBaselineTest {
    private val packageManagerField =
        ConfigurationManager::class.java.getDeclaredField("iPackageManager").apply {
            isAccessible = true
        }

    @BeforeTest
    fun installPackageManagerWithoutTargets() {
        packageManagerField.set(ConfigurationManager, packageManager(emptyArray()))
    }

    @AfterTest
    fun clearPackageManager() {
        packageManagerField.set(ConfigurationManager, null)
        KeyMintSecurityLevelInterceptor.clearAllGeneratedKeys("host test cleanup")
    }

    @Test
    fun unsupportedMethodForUnknownUidContinuesPlatformWithoutDecodingParcel() {
        val interceptor =
            KeyMintSecurityLevelInterceptor(
                interfaceProxy(IKeystoreSecurityLevel::class.java),
                SecurityLevel.TRUSTED_ENVIRONMENT,
                FixtureInterceptionPolicy(
                    ApprovedFixtureProfileSource { null },
                    FixturePackageResolver { _, _ -> null },
                    targetDaemonPid = 222,
                ),
            )

        val result =
            interceptor.onPreTransact(
                txId = 1,
                target = interfaceProxy(IBinder::class.java),
                code = Int.MAX_VALUE,
                flags = 0,
                callingUid = 91_337,
                callingPid = 44,
                data = uninitializedParcel(),
            )

        assertSame(BinderInterceptor.TransactionResult.ContinueAndSkipPost, result)
    }

    @Test
    fun platformCreatePathClosesAnUnclaimedOriginDeathLease() {
        val interceptor = interceptor(platformPolicy())
        val lease = FakeOriginProcessDeathLease()

        val result =
            interceptor.onPreTransactWithOriginDeath(
                txId = 5,
                target = interfaceProxy(IBinder::class.java),
                code = transactionCode("createOperation"),
                flags = 0,
                callingUid = 91_337,
                callingPid = 44,
                data = uninitializedParcel(),
                originDeathLease = lease,
            )

        assertSame(BinderInterceptor.TransactionResult.ContinueAndSkipPost, result)
        assertTrue(lease.closed.get())
    }

    @Test
    fun uidZeroSecurityLevelHookStopsSupportedGenerateKeyBeforePolicyOrParcelDecode() {
        val interceptor =
            KeyMintSecurityLevelInterceptor(
                interfaceProxy(IKeystoreSecurityLevel::class.java),
                SecurityLevel.TRUSTED_ENVIRONMENT,
                FixtureInterceptionPolicy(
                    ApprovedFixtureProfileSource {
                        error("UID 0 must return before approved profile resolution")
                    },
                    FixturePackageResolver { _, _ ->
                        error("UID 0 must return before package resolution")
                    },
                    targetDaemonPid = 222,
                ),
            )
        val generateKeyCode = transactionCode("generateKey")
        assertNotEquals(-1, generateKeyCode, "host stub must expose generateKey")

        val result =
            interceptor.onPreTransact(
                txId = 4,
                target = interfaceProxy(IBinder::class.java),
                code = generateKeyCode,
                flags = 0,
                callingUid = 0,
                callingPid = 44,
                data = uninitializedParcel(),
            )

        assertSame(BinderInterceptor.TransactionResult.ContinueAndSkipPost, result)
    }

    @Test
    fun hostStubExposesDistinctSecurityLevelTransactionCodes() {
        val transactionCodes =
            setOf(
                transactionCode("createOperation"),
                transactionCode("generateKey"),
                transactionCode("importKey"),
            )

        assertEquals(3, transactionCodes.size)
        assertFalse(-1 in transactionCodes)
    }

    @Test
    fun importKeyRunsPostHookCleanupForPlatformCaller() {
        val interceptor = interceptor(platformPolicy())
        val code = transactionCode("importKey")

        val preResult =
            interceptor.onPreTransact(
                txId = 2,
                target = interfaceProxy(IBinder::class.java),
                code = code,
                flags = 0,
                callingUid = 91_337,
                callingPid = 44,
                data = uninitializedParcel(),
            )

        assertSame(BinderInterceptor.TransactionResult.Continue, preResult)
    }

    @Test
    fun unknownHardwareKeyKeepsCreateOperationPostHook() {
        val result = KeyMintSecurityLevelInterceptor.createOperationContinuationFor(null)

        assertSame(BinderInterceptor.TransactionResult.Continue, result)
        val generatedKeyInfo =
            KeyMintSecurityLevelInterceptor.GeneratedKeyInfo(
                KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair(),
                null,
                9_999,
                KeyEntryResponse(),
            )
        assertNull(KeyMintSecurityLevelInterceptor.createOperationContinuationFor(generatedKeyInfo))
    }

    private fun interceptor(policy: FixtureInterceptionPolicy) =
        KeyMintSecurityLevelInterceptor(
            interfaceProxy(IKeystoreSecurityLevel::class.java),
            SecurityLevel.TRUSTED_ENVIRONMENT,
            policy,
        )

    private fun platformPolicy() =
        FixtureInterceptionPolicy(
            ApprovedFixtureProfileSource { null },
            FixturePackageResolver { _, _ -> null },
            targetDaemonPid = 222,
        )

    private fun transactionCode(method: String): Int =
        InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, method)

    private fun packageManager(packages: Array<String>): IPackageManager =
        interfaceProxy(IPackageManager::class.java) { methodName ->
            if (methodName == "getPackagesForUid") packages else null
        }

    private fun uninitializedParcel(): Parcel {
        val unsafeType = Class.forName("sun.misc.Unsafe")
        val field = unsafeType.getDeclaredField("theUnsafe").apply { isAccessible = true }
        val unsafe = field.get(null)
        val allocateInstance = unsafeType.getMethod("allocateInstance", Class::class.java)
        return allocateInstance.invoke(unsafe, Parcel::class.java) as Parcel
    }

    private fun <T> interfaceProxy(type: Class<T>, result: (String) -> Any? = { null }): T {
        val proxy =
            Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ ->
                result(method.name) ?: defaultValue(method.returnType)
            }
        return checkNotNull(type.cast(proxy))
    }

    private fun defaultValue(type: Class<*>): Any? =
        when (type) {
            Boolean::class.javaPrimitiveType -> false
            Byte::class.javaPrimitiveType -> 0.toByte()
            Short::class.javaPrimitiveType -> 0.toShort()
            Int::class.javaPrimitiveType -> 0
            Long::class.javaPrimitiveType -> 0L
            Float::class.javaPrimitiveType -> 0f
            Double::class.javaPrimitiveType -> 0.0
            Char::class.javaPrimitiveType -> '\u0000'
            else -> null
        }
}
