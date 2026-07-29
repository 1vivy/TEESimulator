package org.matrix.TEESimulator.interception.keystore

import android.content.pm.IPackageManager
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor

class Keystore2InterceptorRegistrationTest {
    @Test
    fun strongBoxRegistrationCountIsZero() {
        val registrations = Keystore2Interceptor.interceptedSecurityLevels()

        assertEquals(1, registrations.size)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, registrations.single())
        assertEquals(0, registrations.count { it == SecurityLevel.STRONGBOX })
    }

    @Test
    fun uidZeroMainHookStopsSupportedGetKeyEntryBeforePackageOrParcelDecode() {
        val code =
            InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
        assertNotEquals(-1, code, "host stub must expose getKeyEntry")
        val packageManagerField =
            ConfigurationManager::class.java.getDeclaredField("iPackageManager").apply {
                isAccessible = true
            }
        val packageCacheField =
            ConfigurationManager::class.java.getDeclaredField("uidToPackagesCache").apply {
                isAccessible = true
            }
        val packageCache = packageCacheField.get(ConfigurationManager) as MutableMap<*, *>
        val originalPackageManager = packageManagerField.get(ConfigurationManager)
        packageCache.clear()
        packageManagerField.set(
            ConfigurationManager,
            packageManager {
                throw AssertionError("UID 0 must return before package resolution")
            },
        )

        val result =
            try {
                Keystore2Interceptor.onPreTransact(
                    txId = 7,
                    target = binderProxy(),
                    code = code,
                    flags = 0,
                    callingUid = 0,
                    callingPid = 44,
                    data = uninitializedParcel(),
                )
            } finally {
                packageManagerField.set(ConfigurationManager, originalPackageManager)
                packageCache.clear()
            }

        assertSame(BinderInterceptor.TransactionResult.ContinueAndSkipPost, result)
    }

    private fun binderProxy(): IBinder = interfaceProxy(IBinder::class.java)

    private fun packageManager(result: () -> Array<String>): IPackageManager =
        interfaceProxy(IPackageManager::class.java) { methodName ->
            if (methodName == "getPackagesForUid") result() else null
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
