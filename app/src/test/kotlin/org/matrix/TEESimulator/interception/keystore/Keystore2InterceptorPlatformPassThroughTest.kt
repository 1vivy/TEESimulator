package org.matrix.TEESimulator.interception.keystore

import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor

class Keystore2InterceptorPlatformPassThroughTest {
    @AfterTest
    fun clearGeneratedState() {
        KeyMintSecurityLevelInterceptor.clearAllGeneratedKeys("host test cleanup")
    }

    @Test
    fun getKeyEntryPostHookLeavesThePlatformReplyUnreadAndNeverCreatesGeneratedState() {
        var targetIdentityWasCompared = false
        val service = binderProxy { targetIdentityWasCompared = true }
        val serviceField =
            Keystore2Interceptor::class.java.superclass.getDeclaredField("keystoreService").apply {
                isAccessible = true
            }
        val original = runCatching { serviceField.get(Keystore2Interceptor) }.getOrNull()
        serviceField.set(Keystore2Interceptor, service)
        val getKeyEntry =
            InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
        val reply =
            Parcel.obtain().apply {
                writeNoException()
                setDataPosition(0)
            }

        val result =
            try {
                Keystore2Interceptor.onPostTransact(
                    txId = 19,
                    target = service,
                    code = getKeyEntry,
                    flags = 0,
                    callingUid = 12345,
                    callingPid = 77,
                    data = Parcel.obtain(),
                    reply = reply,
                    resultCode = 0,
                )
            } finally {
                if (original != null) serviceField.set(Keystore2Interceptor, original)
            }

        assertSame(BinderInterceptor.TransactionResult.SkipTransaction, result)
        assertTrue(targetIdentityWasCompared)
        assertEquals(
            0,
            reply.dataPosition(),
            "GET_KEY_ENTRY exclusion must not inspect the platform reply",
        )
        assertTrue(KeyMintSecurityLevelInterceptor.generatedKeys.isEmpty())
    }

    private fun binderProxy(onEquals: () -> Unit): IBinder =
        interfaceProxy(IBinder::class.java, onEquals)

    private fun <T> interfaceProxy(type: Class<T>, onEquals: () -> Unit): T {
        val proxy =
            Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, method, args ->
                when (method.name) {
                    "equals" -> {
                        onEquals()
                        self === args?.singleOrNull()
                    }
                    "hashCode" -> System.identityHashCode(self)
                    else ->
                        when (method.returnType) {
                            Boolean::class.javaPrimitiveType -> false
                            Int::class.javaPrimitiveType -> 0
                            Long::class.javaPrimitiveType -> 0L
                            else -> null
                        }
                }
            }
        return checkNotNull(type.cast(proxy))
    }
}
