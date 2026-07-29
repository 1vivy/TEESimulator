package org.matrix.teesimulator.physicalharness

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Comparator
import java.util.UUID
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec

class DonorStateCodec(private val mac: HandleMac) {
    fun encode(snapshot: DonorStateSnapshot): ByteArray {
        val keys = snapshot.keys.sortedWith(KEY_COMPARATOR)
        val mutations = snapshot.mutations.sortedWith(MUTATION_COMPARATOR)
        val body = encodeBody(keys, mutations)
        val envelope =
            DonorStateWriter(MAX_AUTHENTICATED_BYTES)
                .apply {
                    writeInt(MAGIC)
                    writeUnsignedShort(VERSION)
                    writeUnsignedShort(FLAGS)
                    writeLong(snapshot.revision.toLong())
                    writeInt(body.size)
                    writeFixed(body)
                }
                .toByteArray()
        val signature = signature(envelope)
        return envelope + signature
    }

    fun decode(file: ByteArray): DonorStateSnapshot {
        if (file.size > MAX_FILE_BYTES) throw DonorStateCorruptionException.LimitExceeded()
        if (file.size < MAC_BYTES) throw DonorStateCorruptionException.Truncated()
        val envelope = file.copyOf(file.size - MAC_BYTES)
        val suppliedSignature = file.copyOfRange(file.size - MAC_BYTES, file.size)
        val expectedSignature = signature(envelope)
        if (!MessageDigest.isEqual(expectedSignature, suppliedSignature)) {
            throw DonorStateCorruptionException.AuthenticationFailed()
        }
        return decodeAuthenticated(envelope)
    }

    private fun encodeBody(
        keys: List<DurableKeyRecord>,
        mutations: List<DurableMutationRecord>,
    ): ByteArray =
        DonorStateWriter(MAX_BODY_BYTES)
            .apply {
                writeInt(keys.size)
                keys.forEach { writeKey(it) }
                writeInt(mutations.size)
                mutations.forEach { writeMutation(it) }
            }
            .toByteArray()

    private fun DonorStateWriter.writeKey(key: DurableKeyRecord) {
        writeUuid(key.keyId)
        writeScope(key.scope)
        writeFixed(key.logicalNameHash)
        writeString(key.internalAlias)
        writeUnsignedShort(keyStateTag(key.state))
        val metadata = key.metadata
        writeByte(if (metadata == null) ABSENT else PRESENT)
        if (metadata != null) writeMetadata(metadata)
    }

    private fun DonorStateWriter.writeMutation(mutation: DurableMutationRecord) {
        writeUnsignedShort(kindTag(mutation.kind))
        writeUnsignedShort(phaseTag(mutation.phase))
        writeScope(mutation.scope)
        writeUuid(mutation.mutationId)
        writeFixed(mutation.payloadHash)
        writeUuid(mutation.keyId)
        val intent = mutation.generateIntent
        writeByte(if (intent == null) ABSENT else PRESENT)
        if (intent != null) {
            writeFixed(intent.logicalNameHash)
            writeBytes(intent.challenge)
            writeKeySpec(intent.keySpec)
        }
    }

    private fun DonorStateWriter.writeScope(scope: HandleScope) {
        writeString(scope.pair.targetPin)
        writeString(scope.pair.donorPin)
        writeString(scope.caller.signingCertificateDigest)
        writeString(scope.caller.attestationApplicationIdDigest)
    }

    private fun DonorStateWriter.writeMetadata(metadata: WireKeyMetadata) {
        writeBytes(metadata.attestationChallenge)
        writeBytes(metadata.publicKey)
        val certificates = metadata.certificateChain
        writeUnsignedShort(certificates.size)
        certificates.forEach(::writeBytes)
        writeKeySpec(metadata.keySpec)
    }

    private fun DonorStateWriter.writeKeySpec(spec: WireKeySpec) {
        requireFixedKeySpec(spec)
        writeUnsignedShort(KEY_ALGORITHM_EC)
        writeUnsignedShort(EC_CURVE_P256)
        writeUnsignedShort(DIGEST_SHA256)
        writeUnsignedShort(KEY_PURPOSE_SIGN)
    }

    private fun decodeAuthenticated(envelope: ByteArray): DonorStateSnapshot {
        val reader = DonorStateReader(envelope)
        if (
            reader.readInt() != MAGIC ||
                reader.readUnsignedShort() != VERSION ||
                reader.readUnsignedShort() != FLAGS
        ) {
            throw DonorStateCorruptionException.UnsupportedEnvelope()
        }
        val revision = reader.readLong().toULong()
        val bodyLength = reader.readInt()
        if (bodyLength < 0 || bodyLength > MAX_BODY_BYTES) {
            throw DonorStateCorruptionException.LimitExceeded()
        }
        if (bodyLength > reader.remaining) throw DonorStateCorruptionException.Truncated()
        if (bodyLength < reader.remaining) throw DonorStateCorruptionException.TrailingData()
        val body = DonorStateReader(reader.readFixed(bodyLength))
        reader.requireFinished()
        val keys = List(body.readCount(DonorStateLimits.MAX_RECORDS)) { body.readKey() }
        val mutations = List(body.readCount(DonorStateLimits.MAX_RECORDS)) { body.readMutation() }
        body.requireFinished()
        requireCanonical(keys, mutations)
        return DonorStateSnapshot(revision, keys, mutations)
    }

    private fun DonorStateReader.readKey(): DurableKeyRecord {
        val keyId = readUuid()
        val scope = readScope()
        val logicalNameHash = readFixed(DonorStateLimits.HASH_BYTES)
        val alias = readString(1, DonorStateLimits.MAX_ALIAS_BYTES)
        val state = keyStateForTag(readUnsignedShort())
        val metadata =
            when (readPresence()) {
                false -> null
                true -> readMetadata(state)
            }
        return DurableKeyRecord(keyId, scope, logicalNameHash, alias, state, metadata)
    }

    private fun DonorStateReader.readMutation(): DurableMutationRecord {
        val kind = kindForTag(readUnsignedShort())
        val phase = phaseForTag(readUnsignedShort())
        val scope = readScope()
        val mutationId = readUuid()
        val payloadHash = readFixed(DonorStateLimits.HASH_BYTES)
        val keyId = readUuid()
        val intent =
            when (readPresence()) {
                false -> null
                true ->
                    GenerateIntent(
                        readFixed(DonorStateLimits.HASH_BYTES),
                        readBytes(1, DonorStateLimits.MAX_CHALLENGE_BYTES),
                        readKeySpec(),
                    )
            }
        return DurableMutationRecord(kind, phase, scope, mutationId, payloadHash, keyId, intent)
    }

    private fun DonorStateReader.readScope() =
        HandleScope(
            PairIdentity(
                readString(1, DonorStateLimits.MAX_SCOPE_STRING_BYTES),
                readString(1, DonorStateLimits.MAX_SCOPE_STRING_BYTES),
            ),
            WireCallerIdentity(
                readString(1, DonorStateLimits.MAX_SCOPE_STRING_BYTES),
                readString(1, DonorStateLimits.MAX_SCOPE_STRING_BYTES),
            ),
        )

    private fun DonorStateReader.readMetadata(state: KeyState): WireKeyMetadata {
        val challenge = readBytes(1, DonorStateLimits.MAX_CHALLENGE_BYTES)
        val publicKey = readBytes(1, DonorStateLimits.MAX_PUBLIC_KEY_BYTES)
        val certificateCount = readUnsignedShort()
        if (certificateCount !in 1..DonorStateLimits.MAX_CERTIFICATES) {
            throw DonorStateCorruptionException.LimitExceeded()
        }
        val certificates =
            List(certificateCount) { readBytes(1, DonorStateLimits.MAX_CERTIFICATE_BYTES) }
        return WireKeyMetadata(state, challenge, publicKey, certificates, readKeySpec())
    }

    private fun DonorStateReader.readKeySpec(): WireKeySpec {
        if (
            readUnsignedShort() != KEY_ALGORITHM_EC ||
                readUnsignedShort() != EC_CURVE_P256 ||
                readUnsignedShort() != DIGEST_SHA256 ||
                readUnsignedShort() != KEY_PURPOSE_SIGN
        ) {
            throw DonorStateCorruptionException.UnknownTag()
        }
        return WireKeySpec(
            WireKeyAlgorithm.EC,
            WireEcCurve.P256,
            WireDigest.SHA256,
            WireKeyPurpose.SIGN,
        )
    }

    private fun DonorStateReader.readPresence(): Boolean =
        when (readUnsignedByte()) {
            ABSENT -> false
            PRESENT -> true
            else -> throw DonorStateCorruptionException.UnknownTag()
        }

    private fun signature(envelope: ByteArray): ByteArray {
        val domain = DOMAIN.toByteArray(StandardCharsets.US_ASCII)
        val input =
            DonorStateWriter(MAX_MAC_INPUT_BYTES)
                .apply {
                    writeBytes(domain)
                    writeBytes(envelope)
                }
                .toByteArray()
        val output = mac.sign(input)
        if (output.size != MAC_BYTES) {
            throw DonorStateCorruptionException.InvalidMacOutput()
        }
        return output.copyOf()
    }

    private fun requireCanonical(
        keys: List<DurableKeyRecord>,
        mutations: List<DurableMutationRecord>,
    ) {
        if (
            keys != keys.sortedWith(KEY_COMPARATOR) ||
                mutations != mutations.sortedWith(MUTATION_COMPARATOR)
        ) {
            throw DonorStateQuarantineException.NonCanonicalOrder()
        }
    }

    companion object {
        const val MAX_FILE_BYTES = 32 * 1024 * 1024

        private const val MAGIC = 0x54445331
        private const val VERSION = 1
        private const val FLAGS = 0
        private const val HEADER_BYTES = 20
        private const val MAC_BYTES = 32
        private const val MAX_AUTHENTICATED_BYTES = MAX_FILE_BYTES - MAC_BYTES
        private const val MAX_BODY_BYTES = MAX_AUTHENTICATED_BYTES - HEADER_BYTES
        private const val MAX_MAC_INPUT_BYTES = MAX_FILE_BYTES + 64
        private const val DOMAIN = "teesim-state-file-v1"
        private const val ABSENT = 0
        private const val PRESENT = 1
        private const val KEY_ALGORITHM_EC = 1
        private const val EC_CURVE_P256 = 1
        private const val DIGEST_SHA256 = 1
        private const val KEY_PURPOSE_SIGN = 1

        private val KEY_COMPARATOR =
            Comparator<DurableKeyRecord> { left, right -> compareUuid(left.keyId, right.keyId) }
        private val MUTATION_COMPARATOR =
            Comparator<DurableMutationRecord> { left, right ->
                compareScope(left.scope, right.scope).takeIf { it != 0 }
                    ?: kindTag(left.kind).compareTo(kindTag(right.kind)).takeIf { it != 0 }
                    ?: compareUuid(left.mutationId, right.mutationId)
            }

        private fun keyStateTag(state: KeyState): Int =
            when (state) {
                KeyState.ABSENT -> throw DonorStateQuarantineException.InvalidRecord()
                KeyState.CREATING -> 0x0001
                KeyState.ACTIVE -> 0x0002
                KeyState.SUPERSEDED -> 0x0003
                KeyState.DELETE_PENDING -> 0x0004
                KeyState.DELETED -> 0x0005
                KeyState.QUARANTINED -> 0x0006
            }

        private fun keyStateForTag(tag: Int): KeyState =
            when (tag) {
                0x0001 -> KeyState.CREATING
                0x0002 -> KeyState.ACTIVE
                0x0003 -> KeyState.SUPERSEDED
                0x0004 -> KeyState.DELETE_PENDING
                0x0005 -> KeyState.DELETED
                0x0006 -> KeyState.QUARANTINED
                else -> throw DonorStateCorruptionException.UnknownTag()
            }

        private fun kindTag(kind: DurableMutationKind): Int =
            when (kind) {
                DurableMutationKind.GENERATE -> 0x0001
                DurableMutationKind.DELETE -> 0x0002
            }

        private fun kindForTag(tag: Int): DurableMutationKind =
            when (tag) {
                0x0001 -> DurableMutationKind.GENERATE
                0x0002 -> DurableMutationKind.DELETE
                else -> throw DonorStateCorruptionException.UnknownTag()
            }

        private fun phaseTag(phase: DurableMutationPhase): Int =
            when (phase) {
                DurableMutationPhase.PREPARED -> 0x0001
                DurableMutationPhase.COMMITTED -> 0x0002
                DurableMutationPhase.QUARANTINED -> 0x0003
            }

        private fun phaseForTag(tag: Int): DurableMutationPhase =
            when (tag) {
                0x0001 -> DurableMutationPhase.PREPARED
                0x0002 -> DurableMutationPhase.COMMITTED
                0x0003 -> DurableMutationPhase.QUARANTINED
                else -> throw DonorStateCorruptionException.UnknownTag()
            }

        private fun compareUuid(left: UUID, right: UUID): Int =
            compareUnsigned(
                ByteBuffer.allocate(16)
                    .putLong(left.mostSignificantBits)
                    .putLong(left.leastSignificantBits)
                    .array(),
                ByteBuffer.allocate(16)
                    .putLong(right.mostSignificantBits)
                    .putLong(right.leastSignificantBits)
                    .array(),
            )

        private fun compareScope(left: HandleScope, right: HandleScope): Int {
            left.canonicalFields().zip(right.canonicalFields()).forEach { (leftField, rightField) ->
                val comparison = compareUnsigned(leftField, rightField)
                if (comparison != 0) return comparison
            }
            return 0
        }

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            for (index in 0 until minOf(left.size, right.size)) {
                val comparison =
                    (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
                if (comparison != 0) return comparison
            }
            return left.size.compareTo(right.size)
        }
    }
}
