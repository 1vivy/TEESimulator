package org.matrix.teesimulator.physicalharness

import java.nio.ByteBuffer
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec

internal val testKeySpec =
    WireKeySpec(WireKeyAlgorithm.EC, WireEcCurve.P256, WireDigest.SHA256, WireKeyPurpose.SIGN)

internal fun testScope(seed: Int = 1) =
    HandleScope(
        PairIdentity("target-$seed", "donor-$seed"),
        WireCallerIdentity("signer-$seed", "application-$seed"),
    )

internal fun testMetadata(state: KeyState = KeyState.ACTIVE, seed: Int = 1) =
    WireKeyMetadata(
        state,
        testBytes(32, seed),
        testBytes(65, seed + 1),
        listOf(testBytes(96, seed + 2), testBytes(97, seed + 3)),
        testKeySpec,
    )

internal fun testKey(
    id: Int = 1,
    scope: HandleScope = testScope(),
    alias: String = testAlias(id),
    logicalNameHash: ByteArray = testBytes(32, id + 10),
    state: KeyState = KeyState.ACTIVE,
    metadata: WireKeyMetadata? = if (state == KeyState.CREATING) null else testMetadata(state, id),
) = DurableKeyRecord(testUuid(id), scope, logicalNameHash, alias, state, metadata)

internal fun testMutation(
    id: Int = 20,
    kind: DurableMutationKind = DurableMutationKind.GENERATE,
    phase: DurableMutationPhase = DurableMutationPhase.COMMITTED,
    key: DurableKeyRecord = testKey(),
    challenge: ByteArray? = null,
) =
    DurableMutationRecord(
        kind,
        phase,
        key.scope,
        testUuid(id),
        testBytes(32, id + 1),
        key.keyId,
        if (kind == DurableMutationKind.GENERATE) {
            GenerateIntent(
                key.logicalNameHash,
                challenge ?: key.metadata?.attestationChallenge ?: testBytes(32, id + 2),
                testKeySpec,
            )
        } else {
            null
        },
    )

internal fun testSnapshot(
    revision: ULong = 7uL,
    keys: List<DurableKeyRecord> = listOf(testKey()),
    mutations: List<DurableMutationRecord> = listOf(testMutation(key = keys.single())),
) = DonorStateSnapshot(revision, keys, mutations)

internal fun assertSnapshotEquals(expected: DonorStateSnapshot, actual: DonorStateSnapshot) {
    assertEquals(expected.revision, actual.revision)
    assertEquals(expected.keys.size, actual.keys.size)
    expected.keys.zip(actual.keys).forEach { (left, right) ->
        assertEquals(left.keyId, right.keyId)
        assertEquals(left.scope, right.scope)
        assertContentEquals(left.logicalNameHash, right.logicalNameHash)
        assertEquals(left.internalAlias, right.internalAlias)
        assertEquals(left.state, right.state)
        assertMetadataEquals(left.metadata, right.metadata)
    }
    assertEquals(expected.mutations.size, actual.mutations.size)
    expected.mutations.zip(actual.mutations).forEach { (left, right) ->
        assertEquals(left.kind, right.kind)
        assertEquals(left.phase, right.phase)
        assertEquals(left.scope, right.scope)
        assertEquals(left.mutationId, right.mutationId)
        assertContentEquals(left.payloadHash, right.payloadHash)
        assertEquals(left.keyId, right.keyId)
        assertIntentEquals(left.generateIntent, right.generateIntent)
    }
}

private fun assertMetadataEquals(expected: WireKeyMetadata?, actual: WireKeyMetadata?) {
    if (expected == null || actual == null) {
        assertEquals(expected, actual)
        return
    }
    assertEquals(expected.state, actual.state)
    assertContentEquals(expected.attestationChallenge, actual.attestationChallenge)
    assertContentEquals(expected.publicKey, actual.publicKey)
    assertEquals(expected.certificateChain.size, actual.certificateChain.size)
    expected.certificateChain.zip(actual.certificateChain).forEach { (left, right) ->
        assertContentEquals(left, right)
    }
    assertEquals(expected.keySpec, actual.keySpec)
}

private fun assertIntentEquals(expected: GenerateIntent?, actual: GenerateIntent?) {
    if (expected == null || actual == null) {
        assertEquals(expected, actual)
        return
    }
    assertContentEquals(expected.logicalNameHash, actual.logicalNameHash)
    assertContentEquals(expected.challenge, actual.challenge)
    assertEquals(expected.keySpec, actual.keySpec)
}

internal fun testUuid(value: Int) = UUID(0, value.toLong())

internal fun testAlias(value: Int) =
    "teesim_donor_key_v1_${testUuid(value).toString().replace("-", "")}"

internal fun testBytes(size: Int, seed: Int) = ByteArray(size) { (seed + it).toByte() }

internal class TestHandleMac(keyBytes: ByteArray = testBytes(32, 90)) : HandleMac {
    private val key = SecretKeySpec(keyBytes.copyOf(), "HmacSHA256")

    override fun sign(input: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(key) }.doFinal(input)
}

internal fun resign(frame: ByteArray, mac: HandleMac): ByteArray {
    val signed = frame.copyOf(frame.size - 32)
    val input =
        ByteBuffer.allocate(4 + STATE_DOMAIN.size + 4 + signed.size)
            .putInt(STATE_DOMAIN.size)
            .put(STATE_DOMAIN)
            .putInt(signed.size)
            .put(signed)
            .array()
    return signed + mac.sign(input)
}

internal fun ByteArray.mutated(index: Int): ByteArray =
    copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

internal fun ByteArray.indexOfBytes(needle: ByteArray, fromIndex: Int = 0): Int {
    if (needle.isEmpty()) return fromIndex.coerceAtMost(size)
    for (index in fromIndex..size - needle.size) {
        if (needle.indices.all { this[index + it] == needle[it] }) return index
    }
    return -1
}

internal fun assertGenericMessage(failure: Throwable) {
    val message = failure.message.orEmpty()
    listOf("internal-", "teesim_donor_key_v1_", "target-", "donor-", "signer-", "application-")
        .forEach { check(!message.contains(it)) }
}

private val STATE_DOMAIN = "teesim-state-file-v1".encodeToByteArray()
