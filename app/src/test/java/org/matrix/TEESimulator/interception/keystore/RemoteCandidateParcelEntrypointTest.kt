package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import java.lang.reflect.Proxy
import java.math.BigInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.interception.keystore.shim.CandidateKeyMintParcelCodec
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.rka.candidate.CandidateGenerateRequest
import org.matrix.TEESimulator.rka.candidate.CandidateRuntime
import org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry

class RemoteCandidateParcelEntrypointTest {
    @After
    fun resetRegistry() {
        CandidateRuntimeRegistry.initializeLifecycle()
    }

    @Test
    fun keystorePreAndPostEntrypointsReachCandidateListRoute() {
        val fixture = ProductionFixture()
        fixture.service
            .generate(CandidateGenerateRequest(fixture.id, fixture.identity, fixture.shape))
            .remoteSuccess()
        fixture.backend.calls.clear()
        publishRuntime(fixture.runtime)
        val parcel = parcel()
        val target = fakeBinder()
        val code = transactionCode("GET_NUMBER_OF_ENTRIES_TRANSACTION")

        assertNotNull(
            Keystore2Interceptor.onPreTransact(991, target, code, 0, fixture.uid, 1, parcel)
        )
        assertEquals(listOf("list"), fixture.backend.calls)
        val post = runCatching {
            Keystore2Interceptor.onPostTransact(
                991,
                target,
                code,
                0,
                fixture.uid,
                1,
                parcel,
                parcel,
                0,
            )
        }
        assertTrue(
            post.getOrNull() != null ||
                post.exceptionOrNull() is UninitializedPropertyAccessException
        )
    }

    @Test
    fun keyMintPreEntrypointReachesCandidateGenerateRouteBeforeStubReplyFailure() {
        val fixture = ProductionFixture()
        fixture.backend.failureStage = "generate"
        publishRuntime(fixture.runtime)
        val interceptor =
            KeyMintSecurityLevelInterceptor(
                fakeInterface(IKeystoreSecurityLevel::class.java),
                SecurityLevel.TRUSTED_ENVIRONMENT,
            )
        interceptor.javaClass.getDeclaredField("candidateRawParcelSource").let {
            it.isAccessible = true
            it.set(interceptor) { _: Parcel ->
                CandidateKeyMintParcelCodec.encodeGenerate(descriptor("entrypoint"), attestation())
            }
        }
        val outcome = runCatching {
            interceptor.onPreTransact(
                992,
                fakeBinder(),
                keyMintTransactionCode("GENERATE_KEY_TRANSACTION"),
                0,
                fixture.uid,
                1,
                parcel(),
            )
        }
        assertTrue(outcome.getOrNull() != null || outcome.exceptionOrNull() is NullPointerException)
        assertEquals(listOf("generate"), fixture.backend.calls)
    }

    @Test
    fun candidateKeyMintRawCodecIsCanonicalAndBounded() {
        val raw = CandidateKeyMintParcelCodec.encodeGenerate(descriptor("codec"), attestation())
        val decoded = CandidateKeyMintParcelCodec.decodeGenerate(raw)
        assertEquals("codec", decoded.descriptor.alias)
        assertEquals(listOf(2), decoded.attestation.purpose)
        assertEquals(listOf(Digest.SHA_2_256), decoded.attestation.digest)
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKeyMintParcelCodec.decodeGenerate(raw + 0)
        }
        assertThrows(java.io.EOFException::class.java) {
            CandidateKeyMintParcelCodec.decodeGenerate(raw.copyOf(raw.size - 1))
        }
    }

    private fun transactionCode(name: String): Int =
        Keystore2Interceptor::class.java.getDeclaredField(name).let {
            it.isAccessible = true
            it.getInt(Keystore2Interceptor)
        }

    private fun keyMintTransactionCode(name: String): Int =
        KeyMintSecurityLevelInterceptor::class.java.getDeclaredField(name).let {
            it.isAccessible = true
            it.getInt(null)
        }

    private fun parcel(): Parcel =
        Parcel::class.java.getDeclaredConstructor().let {
            it.isAccessible = true
            it.newInstance()
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

    private fun fakeBinder(): IBinder = fakeInterface(IBinder::class.java)

    @Suppress("UNCHECKED_CAST")
    private fun <T> fakeInterface(type: Class<T>): T =
        Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ ->
            when (method.returnType) {
                Boolean::class.javaPrimitiveType -> false
                Int::class.javaPrimitiveType -> 0
                Long::class.javaPrimitiveType -> 0L
                else -> null
            }
        } as T

    private fun attestation() =
        KeyMintAttestation(
            256,
            Algorithm.EC,
            EcCurve.P_256,
            "secp256r1",
            null,
            emptyList(),
            emptyList(),
            listOf(2),
            listOf(Digest.SHA_2_256),
            null,
            BigInteger.ONE,
            null,
            null,
            null,
            byteArrayOf(1),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            emptyList(),
        )
}
