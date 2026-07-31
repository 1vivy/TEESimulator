package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import java.lang.reflect.Proxy
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.rka.candidate.CandidateRuntime
import org.matrix.TEESimulator.rka.candidate.CandidateRuntimeRegistry
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class RemoteCandidateParcelEntrypointTest {
    @After
    fun resetRegistry() {
        CandidateRuntimeRegistry.initializeLifecycle()
    }

    @Test
    fun keyMintTransactionParsesRoutesAndReturnsDrivableOperation() {
        // Given a published candidate runtime and real platform Parcel transactions.
        val fixture = ProductionFixture()
        publishRuntime(fixture.runtime)
        val interceptor =
            KeyMintSecurityLevelInterceptor(
                fakeInterface(IKeystoreSecurityLevel::class.java),
                SecurityLevel.TRUSTED_ENVIRONMENT,
            )

        // When generateKey and createOperation enter the production transaction handler.
        val generateResult =
            interceptor.onPreTransact(
                992,
                fakeBinder(),
                transactionCode("GENERATE_KEY_TRANSACTION"),
                0,
                fixture.uid,
                1,
                generateParcel(fixture.id.alias),
            )
        val createResult =
            interceptor.onPreTransact(
                993,
                fakeBinder(),
                transactionCode("CREATE_OPERATION_TRANSACTION"),
                0,
                fixture.uid,
                1,
                createOperationParcel(fixture.id.alias),
            )
        val operation =
            (createResult as BinderInterceptor.TransactionResult.OverrideReply).reply.run {
                setDataPosition(0)
                readException()
                checkNotNull(
                    checkNotNull(readTypedObject(CreateOperationResponse.CREATOR)).iOperation
                )
            }
        operation.updateAad(byteArrayOf(1))
        val update = operation.update(byteArrayOf(2))
        val finish = operation.finish(byteArrayOf(3), null)

        // Then both parsing and remote routing are observable through the handler reply.
        assertTrue(generateResult is BinderInterceptor.TransactionResult.OverrideReply)
        assertArrayEquals(ByteArray(0), update)
        assertArrayEquals(byteArrayOf(8, 9), finish)
        assertEquals(
            listOf("generate", "begin", "updateAad", "update", "finish"),
            fixture.backend.calls,
        )
    }

    private fun generateParcel(alias: String): Parcel =
        Parcel.obtain().apply {
            writeInterfaceToken(IKeystoreSecurityLevel.DESCRIPTOR)
            writeTypedObject(descriptor(alias), 0)
            writeTypedObject(null, 0)
            writeTypedArray(
                arrayOf(
                    parameter(Tag.KEY_SIZE, KeyParameterValue.integer(256)),
                    parameter(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.EC)),
                    parameter(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256)),
                    parameter(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.SIGN)),
                    parameter(Tag.DIGEST, KeyParameterValue.digest(Digest.SHA_2_256)),
                    parameter(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(byteArrayOf(1))),
                ),
                0,
            )
            setDataPosition(0)
        }

    private fun createOperationParcel(alias: String): Parcel =
        Parcel.obtain().apply {
            writeInterfaceToken(IKeystoreSecurityLevel.DESCRIPTOR)
            writeTypedObject(descriptor(alias), 0)
            writeTypedArray(emptyArray<KeyParameter>(), 0)
            writeBoolean(false)
            setDataPosition(0)
        }

    private fun parameter(tag: Int, value: KeyParameterValue) =
        KeyParameter().apply {
            this.tag = tag
            this.value = value
        }

    private fun descriptor(alias: String) =
        KeyDescriptor().apply {
            domain = Domain.APP
            nspace = -1
            this.alias = alias
            blob = null
        }

    private fun transactionCode(name: String): Int =
        KeyMintSecurityLevelInterceptor::class.java.getDeclaredField(name).let {
            it.isAccessible = true
            it.getInt(null)
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
}
