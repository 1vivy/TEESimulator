package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.SecurityLevel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import java.lang.reflect.Proxy
import java.math.BigInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.rka.candidate.CandidateGenerateRequest
import org.matrix.TEESimulator.rka.candidate.CandidateRuntime
import org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry

class RemoteCandidateInterceptorHandlerTest {
    @After
    fun resetRegistry() {
        CandidateRuntimeRegistry.initializeLifecycle()
    }

    @Test
    fun keyMintHandlerRoutesExactShapeAndRejectsPurposeOrDigestExtras() {
        val fixture = ProductionFixture()
        publishRuntime(fixture.runtime)
        fixture.backend.failureStage = "generate"
        val interceptor =
            KeyMintSecurityLevelInterceptor(fakeSecurityLevel(), SecurityLevel.TRUSTED_ENVIRONMENT)
        val route =
            interceptor.javaClass.getDeclaredMethod(
                "routeCandidateGenerate",
                Int::class.javaPrimitiveType,
                KeyDescriptor::class.java,
                KeyMintAttestation::class.java,
            )
        route.isAccessible = true

        assertReplyAttempt {
            route.invoke(interceptor, fixture.uid, descriptor("exact"), attestation())
        }
        assertReplyAttempt {
            route.invoke(
                interceptor,
                fixture.uid,
                descriptor("purpose-extra"),
                attestation(purpose = listOf(2, 3)),
            )
        }
        assertReplyAttempt {
            route.invoke(
                interceptor,
                fixture.uid,
                descriptor("digest-extra"),
                attestation(digest = listOf(Digest.SHA_2_256, Digest.NONE)),
            )
        }
        assertEquals(listOf("generate"), fixture.backend.calls)
    }

    @Test
    fun keystoreHandlersRouteListGetGrantAndDelete() {
        val fixture = ProductionFixture()
        fixture.service
            .generate(CandidateGenerateRequest(fixture.id, fixture.identity, fixture.shape))
            .remoteSuccess()
        fixture.backend.calls.clear()
        publishRuntime(fixture.runtime)

        val list =
            privateMethod(
                "routeCandidateList",
                Long::class.java,
                Int::class.java,
                Boolean::class.java,
            )
        assertNull(list.invoke(Keystore2Interceptor, 91L, fixture.uid, false))
        val pending = ListEntriesHandler::class.java.getDeclaredField("pendingRemoteKeys")
        pending.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val cached = pending.get(ListEntriesHandler) as MutableMap<Long, *>
        assertTrue(cached.containsKey(91L))
        cached.remove(91L)

        fixture.backend.failureStage = "get"
        val key =
            privateMethod(
                "routeCandidateKey",
                Int::class.java,
                Int::class.java,
                KeyDescriptor::class.java,
            )
        assertReplyAttempt {
            key.invoke(
                Keystore2Interceptor,
                transactionCode("GET_KEY_ENTRY_TRANSACTION"),
                fixture.uid,
                descriptor(fixture.id.alias),
            )
        }
        fixture.backend.failureStage = null
        assertReplyAttempt {
            key.invoke(
                Keystore2Interceptor,
                transactionCode("DELETE_KEY_TRANSACTION"),
                fixture.uid,
                descriptor(fixture.id.alias),
            )
        }
        val grant =
            privateMethod(
                "routeCandidateGrant",
                Int::class.java,
                KeyDescriptor::class.java,
                Int::class.java,
            )
        assertReplyAttempt {
            grant.invoke(Keystore2Interceptor, fixture.uid, descriptor(fixture.id.alias), 7)
        }
        assertEquals(listOf("list", "get", "get"), fixture.backend.calls)
    }

    private fun assertReplyAttempt(block: () -> Any?) {
        val outcome = runCatching(block)
        val failure = outcome.exceptionOrNull()
        assertTrue(failure == null || failure is java.lang.reflect.InvocationTargetException)
    }

    private fun privateMethod(name: String, vararg types: Class<*>): java.lang.reflect.Method =
        Keystore2Interceptor::class.java.getDeclaredMethod(name, *types).also {
            it.isAccessible = true
        }

    private fun transactionCode(name: String): Int =
        Keystore2Interceptor::class.java.getDeclaredField(name).let {
            it.isAccessible = true
            it.getInt(Keystore2Interceptor)
        }

    private fun descriptor(alias: String) =
        KeyDescriptor().apply {
            domain = Domain.APP
            nspace = -1
            this.alias = alias
            blob = null
        }

    private fun publishRuntime(runtime: CandidateRuntime) {
        val stateClass =
            Class.forName(
                "org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry\$State\$Authorized"
            )
        val constructor = stateClass.getDeclaredConstructor(CandidateRuntime::class.java)
        constructor.isAccessible = true
        val state = constructor.newInstance(runtime)
        CandidateRuntimeRegistry::class.java.getDeclaredField("state").let {
            it.isAccessible = true
            it.set(CandidateRuntimeRegistry, state)
        }
    }

    private fun fakeSecurityLevel(): IKeystoreSecurityLevel =
        Proxy.newProxyInstance(
            IKeystoreSecurityLevel::class.java.classLoader,
            arrayOf(IKeystoreSecurityLevel::class.java),
        ) { _, method, _ ->
            when (method.returnType) {
                Boolean::class.javaPrimitiveType -> false
                Int::class.javaPrimitiveType -> 0
                Long::class.javaPrimitiveType -> 0L
                else -> null
            }
        } as IKeystoreSecurityLevel

    private fun attestation(
        purpose: List<Int> = listOf(2),
        digest: List<Int> = listOf(Digest.SHA_2_256),
    ) =
        KeyMintAttestation(
            keySize = 256,
            algorithm = Algorithm.EC,
            ecCurve = EcCurve.P_256,
            ecCurveName = "secp256r1",
            origin = null,
            blockMode = emptyList(),
            padding = emptyList(),
            purpose = purpose,
            digest = digest,
            rsaPublicExponent = null,
            certificateSerial = BigInteger.ONE,
            certificateSubject = null,
            certificateNotBefore = null,
            certificateNotAfter = null,
            attestationChallenge = byteArrayOf(1),
            brand = null,
            device = null,
            product = null,
            serial = null,
            imei = null,
            meid = null,
            manufacturer = null,
            model = null,
            secondImei = null,
            activeDateTime = null,
            originationExpireDateTime = null,
            usageExpireDateTime = null,
            usageCountLimit = null,
            callerNonce = null,
            nonce = null,
            unlockedDeviceRequired = null,
            includeUniqueId = null,
            rollbackResistance = null,
            earlyBootOnly = null,
            allowWhileOnBody = null,
            trustedUserPresenceRequired = null,
            trustedConfirmationRequired = null,
            noAuthRequired = null,
            maxUsesPerBoot = null,
            maxBootLevel = null,
            minMacLength = null,
            macLength = null,
            rsaOaepMgfDigest = emptyList(),
        )
}
