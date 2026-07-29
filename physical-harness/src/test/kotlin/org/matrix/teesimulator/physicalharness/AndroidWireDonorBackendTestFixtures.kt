package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.DeleteRequestPayload
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.LifecycleRequestPayload
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.ProtocolVersion
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireRequestEnvelope

internal class PhysicalBackendTestRig {
    val pair = PairIdentity("target-pinned", "donor-pinned")
    val otherPair = PairIdentity("other-target", "other-donor")
    val ownIdentity =
        CallerIdentityCanonicalizer()
            .canonicalize(
                listOf(CallerPackageIdentity("org.example.donor", 1, listOf(byteArrayOf(1))))
            )
    val caller: WireCallerIdentity = ownIdentity.wireIdentity
    val otherCaller = WireCallerIdentity("other-signer", "other-app")
    val stateStore = FakeAuthenticatedDonorStateStore()
    val keyStoreBackend = FakeAndroidKeyStoreBackend(::validMaterial)
    val donor = AndroidKeystoreDonor({ ownIdentity }, keyStoreBackend)
    val authenticator = HandleAuthenticator(TestHandleMac(testBytes(32, 91)))
    private var nextKeyId = 800
    val repository =
        DonorLifecycleRepository(stateStore, AndroidKeystoreDurableKeyStore(donor), authenticator) {
            testUuid(nextKeyId++)
        }
    val process = PhysicalDonorProcess(stateStore, repository, donor, authenticator)

    fun backend(
        sessionId: ByteArray = session(1),
        pair: PairIdentity = this.pair,
        caller: WireCallerIdentity = this.caller,
    ) = process.newSessionBackend(pair, sessionId, caller)

    fun generateCommand(
        generationId: UUID = testUuid(100),
        logicalNameHash: ByteArray = testBytes(32, 10),
        challenge: ByteArray = testBytes(32, 20),
        caller: WireCallerIdentity = this.caller,
    ): BackendGenerate {
        val payload = GenerateRequestPayload(generationId, logicalNameHash, challenge, testKeySpec)
        return BackendGenerate(
            generationId,
            NormalizedWireCodec.payloadHash(payload),
            logicalNameHash,
            challenge,
            testKeySpec,
            caller,
        )
    }

    fun deleteCommand(
        handle: org.matrix.teesimulator.twophone.WireKeyHandle,
        deletionId: UUID = testUuid(200),
        caller: WireCallerIdentity = this.caller,
    ): BackendDelete {
        val payload = DeleteRequestPayload(deletionId, handle)
        return BackendDelete(deletionId, NormalizedWireCodec.payloadHash(payload), handle, caller)
    }

    fun request(
        payload: LifecycleRequestPayload,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        sequence: ULong,
        caller: WireCallerIdentity = this.caller,
    ) =
        WireRequestEnvelope(
            ProtocolVersion.V1,
            derivedSessionId(pair, clientNonce, serverNonce),
            clientNonce,
            serverNonce,
            sequence,
            UUID.randomUUID(),
            NormalizedWireCodec.payloadHash(payload),
            payload.method,
            Instant.parse("2026-07-25T12:00:30Z"),
            caller,
            payload,
        )

    fun session(seed: Int) = testBytes(32, seed)

    private fun validMaterial(challenge: ByteArray) =
        SyntheticAndroidKeyAttestation.material(challenge, ownIdentity.attestationApplicationIdDer)
}

internal fun derivedSessionId(
    pair: PairIdentity,
    clientNonce: ByteArray,
    serverNonce: ByteArray,
): ByteArray =
    canonicalTestBytes(
            "two-phone-v1".encodeToByteArray(),
            pair.targetPin.encodeToByteArray(),
            pair.donorPin.encodeToByteArray(),
            clientNonce,
            serverNonce,
        )
        .let { MessageDigest.getInstance("SHA-256").digest(it) }

private fun canonicalTestBytes(vararg values: ByteArray): ByteArray =
    ByteArrayOutputStream()
        .also { output ->
            DataOutputStream(output).use { stream ->
                values.forEach {
                    stream.writeInt(it.size)
                    stream.write(it)
                }
            }
        }
        .toByteArray()
