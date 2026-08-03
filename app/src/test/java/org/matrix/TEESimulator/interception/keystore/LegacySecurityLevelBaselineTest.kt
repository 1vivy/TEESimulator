package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.IKeystoreService
import java.lang.reflect.Proxy
import org.junit.Assert.assertEquals
import org.junit.Test

class LegacySecurityLevelBaselineTest {
    @Test
    fun setupRegistersAndLoadsTeeAndStrongBox() {
        val trace = RegistrationTrace()
        val levels =
            mapOf(
                SecurityLevel.TRUSTED_ENVIRONMENT to securityLevel(),
                SecurityLevel.STRONGBOX to securityLevel(),
            )
        val service = service(trace) { level -> levels[level] }

        invokeSetup(service, trace)

        val expected = listOf(SecurityLevel.TRUSTED_ENVIRONMENT, SecurityLevel.STRONGBOX)
        assertEquals(expected, trace.resolved)
        assertEquals(expected, trace.registered)
        assertEquals(expected, trace.loaded)
    }

    @Test
    fun setupSkipsUnavailableStrongBox() {
        val trace = RegistrationTrace()
        val tee = securityLevel()
        val service =
            service(trace) { level ->
                if (level == SecurityLevel.TRUSTED_ENVIRONMENT) tee else null
            }

        invokeSetup(service, trace)

        assertEquals(
            listOf(SecurityLevel.TRUSTED_ENVIRONMENT, SecurityLevel.STRONGBOX),
            trace.resolved,
        )
        assertEquals(listOf(SecurityLevel.TRUSTED_ENVIRONMENT), trace.registered)
        assertEquals(trace.registered, trace.loaded)
    }

    @Test
    fun setupContinuesAfterTeeResolutionError() {
        val trace = RegistrationTrace()
        val strongBox = securityLevel()
        val service =
            service(trace) { level ->
                if (level == SecurityLevel.TRUSTED_ENVIRONMENT) {
                    throw IllegalStateException("TEE unavailable")
                }
                strongBox
            }

        invokeSetup(service, trace)

        assertEquals(
            listOf(SecurityLevel.TRUSTED_ENVIRONMENT, SecurityLevel.STRONGBOX),
            trace.resolved,
        )
        assertEquals(listOf(SecurityLevel.STRONGBOX), trace.registered)
        assertEquals(trace.registered, trace.loaded)
    }

    @Test
    fun returnedSecurityLevelRegistersForCallingUid() {
        val trace = RegistrationTrace()
        val tee = securityLevel()
        val method =
            Keystore2Interceptor::class.java.declaredMethods.firstOrNull {
                it.name == "registerReturnedSecurityLevel" && it.parameterCount == 5
            } ?: throw AssertionError("Returned SecurityLevel registration seam missing")
        val registrar = registrar(method.parameterTypes[4], trace)
        method.isAccessible = true

        method.invoke(
            Keystore2Interceptor,
            binder(),
            tee,
            SecurityLevel.TRUSTED_ENVIRONMENT,
            12_345,
            registrar,
        )

        assertEquals(listOf(SecurityLevel.TRUSTED_ENVIRONMENT), trace.registered)
        assertEquals(trace.registered, trace.loaded)
    }

    private fun invokeSetup(service: IKeystoreService, trace: RegistrationTrace) {
        val method =
            Keystore2Interceptor::class.java.declaredMethods.firstOrNull {
                it.name == "setupSecurityLevelInterceptors" && it.parameterCount == 3
            } ?: throw AssertionError("Keystore2Interceptor runtime registration seam missing")
        val registrarType = method.parameterTypes[2]
        val registrar = registrar(registrarType, trace)
        method.isAccessible = true
        method.invoke(Keystore2Interceptor, service, binder(), registrar)
    }

    private fun registrar(registrarType: Class<*>, trace: RegistrationTrace): Any =
        Proxy.newProxyInstance(registrarType.classLoader, arrayOf(registrarType)) {
            _,
            registrarMethod,
            arguments ->
            check(registrarMethod.name == "register")
            val level = arguments!![2] as Int
            trace.registered += level
            val registrationType = registrarMethod.returnType
            Proxy.newProxyInstance(registrationType.classLoader, arrayOf(registrationType)) {
                _,
                registrationMethod,
                _ ->
                check(registrationMethod.name == "loadPersistedKeys")
                trace.loaded += level
                null
            }
        }

    private fun service(
        trace: RegistrationTrace,
        resolve: (Int) -> IKeystoreSecurityLevel?,
    ): IKeystoreService = IKeystoreService { level ->
        trace.resolved += level
        resolve(level)
    }

    private fun securityLevel(): IKeystoreSecurityLevel =
        Proxy.newProxyInstance(
            IKeystoreSecurityLevel::class.java.classLoader,
            arrayOf(IKeystoreSecurityLevel::class.java),
        ) { _, method, _ ->
            error("Unexpected security-level call: ${method.name}")
        } as IKeystoreSecurityLevel

    private fun binder(): IBinder =
        Proxy.newProxyInstance(IBinder::class.java.classLoader, arrayOf(IBinder::class.java)) {
            _,
            method,
            _ ->
            error("Unexpected binder call: ${method.name}")
        } as IBinder

    private data class RegistrationTrace(
        val resolved: MutableList<Int> = mutableListOf(),
        val registered: MutableList<Int> = mutableListOf(),
        val loaded: MutableList<Int> = mutableListOf(),
    )
}
