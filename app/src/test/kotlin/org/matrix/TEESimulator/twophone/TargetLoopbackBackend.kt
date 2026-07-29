package org.matrix.TEESimulator.twophone

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.math.BigInteger
import java.util.Date
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.BackendGeneratedKey
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDonorBackend
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal class TargetLoopbackBackend(private val expectedCaller: WireCallerIdentity) :
    WireDonorBackend {
    val invocations = AtomicInteger()
    val generateCalls = AtomicInteger()
    val beginCalls = AtomicInteger()
    val updateCalls = AtomicInteger()
    val finishCalls = AtomicInteger()
    val abortCalls = AtomicInteger()
    private var generated: KeyPair? = null
    private var operation: WireOperationHandle? = null
    private val transcript = mutableListOf<ByteArray>()

    override fun generate(command: BackendGenerate): BackendGeneratedKey {
        require(command.caller == expectedCaller)
        invocations.incrementAndGet()
        generateCalls.incrementAndGet()
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        generated = keys
        val certificate =
            JcaX509v3CertificateBuilder(
                    X500Name("CN=loopback"),
                    BigInteger.ONE,
                    Date(System.currentTimeMillis() - 1_000),
                    Date(System.currentTimeMillis() + 60_000),
                    X500Name("CN=loopback"),
                    keys.public,
                )
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(keys.private))
        val handle = WireKeyHandle(KEY_ID, HANDLE_BINDING)
        return BackendGeneratedKey(
            handle,
            WireKeyMetadata(
                KeyState.ACTIVE,
                command.challenge,
                keys.public.encoded,
                listOf(certificate.encoded),
                command.keySpec,
            ),
        )
    }

    override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata =
        error("unexpected metadata")

    override fun delete(command: BackendDelete) = error("unexpected delete")

    override fun begin(
        handle: WireKeyHandle,
        spec: WireOperationSpec,
        caller: WireCallerIdentity,
    ): WireOperationHandle {
        require(caller == expectedCaller)
        require(handle.id == KEY_ID)
        invocations.incrementAndGet()
        beginCalls.incrementAndGet()
        return WireOperationHandle(OPERATION_ID, KEY_ID, OPERATION_BINDING).also { operation = it }
    }

    override fun update(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray {
        require(caller == expectedCaller)
        require(operation.id == this.operation?.id)
        invocations.incrementAndGet()
        updateCalls.incrementAndGet()
        transcript += input.copyOf()
        return ByteArray(0)
    }

    override fun finish(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray {
        require(caller == expectedCaller)
        require(operation.id == this.operation?.id)
        invocations.incrementAndGet()
        finishCalls.incrementAndGet()
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(checkNotNull(generated).private)
            transcript.forEach(::update)
            update(input)
            sign()
        }
    }

    override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) {
        require(caller == expectedCaller)
        require(operation.id == this.operation?.id)
        abortCalls.incrementAndGet()
        this.operation = null
    }

    override fun close() = Unit

    companion object {
        val KEY_ID: UUID = UUID.fromString("70000000-0000-0000-0000-000000000001")
        val OPERATION_ID: UUID = UUID.fromString("70000000-0000-0000-0000-000000000002")
        val HANDLE_BINDING = ByteArray(32) { (it + 1).toByte() }
        val OPERATION_BINDING = ByteArray(32) { (it + 33).toByte() }
    }
}
