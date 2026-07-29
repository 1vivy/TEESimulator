package org.matrix.teesimulator.physicalharness

import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec

enum class DurableMutationKind {
    GENERATE,
    DELETE,
}

enum class DurableMutationPhase {
    PREPARED,
    COMMITTED,
    QUARANTINED,
}

class GenerateIntent(logicalNameHash: ByteArray, challenge: ByteArray, val keySpec: WireKeySpec) {
    private val logicalNameHashBytes = logicalNameHash.validFixedHash()
    private val challengeBytes = challenge.validBytes(1, DonorStateLimits.MAX_CHALLENGE_BYTES)

    init {
        requireFixedKeySpec(keySpec)
    }

    val logicalNameHash: ByteArray
        get() = logicalNameHashBytes.copyOf()

    val challenge: ByteArray
        get() = challengeBytes.copyOf()
}

class DurableKeyRecord(
    val keyId: UUID,
    scope: HandleScope,
    logicalNameHash: ByteArray,
    val internalAlias: String,
    val state: KeyState,
    metadata: WireKeyMetadata?,
) {
    private val stableScope = scope.stableCopy()
    private val logicalNameHashBytes = logicalNameHash.validFixedHash()
    private val stableMetadata = metadata?.validatedCopy()

    init {
        validateScope(stableScope)
        requireValidString(internalAlias, DonorStateLimits.MAX_ALIAS_BYTES, requireNonBlank = true)
        if (internalAlias != DonorKeyAliasPolicy.aliasFor(keyId)) invalidRecord()
        when (state) {
            KeyState.ABSENT -> invalidRecord()
            KeyState.CREATING -> if (stableMetadata != null) impossibleState()
            KeyState.ACTIVE,
            KeyState.SUPERSEDED,
            KeyState.DELETE_PENDING,
            KeyState.DELETED -> if (stableMetadata == null) impossibleState()
            KeyState.QUARANTINED -> Unit
        }
        if (stableMetadata != null && stableMetadata.state != state) impossibleState()
    }

    val scope: HandleScope
        get() = stableScope.stableCopy()

    val logicalNameHash: ByteArray
        get() = logicalNameHashBytes.copyOf()

    val metadata: WireKeyMetadata?
        get() = stableMetadata?.defensiveCopy()
}

class DurableMutationRecord(
    val kind: DurableMutationKind,
    val phase: DurableMutationPhase,
    scope: HandleScope,
    val mutationId: UUID,
    payloadHash: ByteArray,
    val keyId: UUID,
    generateIntent: GenerateIntent?,
) {
    private val stableScope = scope.stableCopy()
    private val payloadHashBytes = payloadHash.validFixedHash()
    private val stableGenerateIntent = generateIntent?.defensiveCopy()

    init {
        validateScope(stableScope)
        when (kind) {
            DurableMutationKind.GENERATE -> if (stableGenerateIntent == null) impossibleState()
            DurableMutationKind.DELETE -> if (stableGenerateIntent != null) impossibleState()
        }
    }

    val scope: HandleScope
        get() = stableScope.stableCopy()

    val payloadHash: ByteArray
        get() = payloadHashBytes.copyOf()

    val generateIntent: GenerateIntent?
        get() = stableGenerateIntent?.defensiveCopy()
}

class DonorStateSnapshot(
    val revision: ULong,
    keys: List<DurableKeyRecord>,
    mutations: List<DurableMutationRecord>,
) {
    private val stableKeys = keys.toList()
    private val stableMutations = mutations.toList()

    init {
        if (
            stableKeys.size > DonorStateLimits.MAX_RECORDS ||
                stableMutations.size > DonorStateLimits.MAX_RECORDS
        ) {
            invalidRecord()
        }
        validateUniqueKeys()
        validateMutations()
    }

    val keys: List<DurableKeyRecord>
        get() = stableKeys.toList()

    val mutations: List<DurableMutationRecord>
        get() = stableMutations.toList()

    private fun validateUniqueKeys() {
        if (
            stableKeys.map(DurableKeyRecord::keyId).toSet().size != stableKeys.size ||
                stableKeys.map(DurableKeyRecord::internalAlias).toSet().size != stableKeys.size
        ) {
            throw DonorStateQuarantineException.DuplicateRecord()
        }
        val liveIdentities =
            stableKeys
                .filter { it.state == KeyState.ACTIVE || it.state == KeyState.CREATING }
                .map { LogicalIdentity(it.scope, it.logicalNameHash.asList()) }
        if (liveIdentities.toSet().size != liveIdentities.size) {
            throw DonorStateQuarantineException.DuplicateRecord()
        }
    }

    private fun validateMutations() {
        val identities = stableMutations.map { MutationIdentity(it.scope, it.kind, it.mutationId) }
        if (identities.toSet().size != identities.size) {
            throw DonorStateQuarantineException.DuplicateRecord()
        }
        if (stableMutations.count { it.phase == DurableMutationPhase.PREPARED } > 1) {
            impossibleState()
        }
        val keysById = stableKeys.associateBy(DurableKeyRecord::keyId)
        stableMutations.forEach { mutation ->
            val key =
                keysById[mutation.keyId] ?: throw DonorStateQuarantineException.DanglingReference()
            if (mutation.scope != key.scope) impossibleState()
            validateIntent(mutation, key)
            validatePhase(mutation, key.state)
        }
        stableKeys.forEach { key -> validateRecoveryRecords(key) }
    }

    private fun validateIntent(mutation: DurableMutationRecord, key: DurableKeyRecord) {
        if (mutation.kind != DurableMutationKind.GENERATE) return
        val intent = mutation.generateIntent!!
        if (!MessageDigest.isEqual(intent.logicalNameHash, key.logicalNameHash)) impossibleState()
        val metadata = key.metadata ?: return
        if (
            !MessageDigest.isEqual(intent.challenge, metadata.attestationChallenge) ||
                intent.keySpec != metadata.keySpec
        ) {
            impossibleState()
        }
    }

    private fun validateRecoveryRecords(key: DurableKeyRecord) {
        val mutations = stableMutations.filter { it.keyId == key.keyId }
        val generations = mutations.filter { it.kind == DurableMutationKind.GENERATE }
        if (generations.size != 1) impossibleState()
        val generation = generations.single()
        when (key.state) {
            KeyState.ABSENT -> impossibleState()
            KeyState.CREATING ->
                if (generation.phase != DurableMutationPhase.PREPARED) impossibleState()
            KeyState.ACTIVE,
            KeyState.SUPERSEDED,
            KeyState.DELETE_PENDING,
            KeyState.DELETED ->
                if (generation.phase != DurableMutationPhase.COMMITTED) impossibleState()
            KeyState.QUARANTINED -> Unit
        }
        val deletions = mutations.filter { it.kind == DurableMutationKind.DELETE }
        when (key.state) {
            KeyState.DELETE_PENDING ->
                if (deletions.count { it.phase == DurableMutationPhase.PREPARED } != 1) {
                    impossibleState()
                }
            KeyState.DELETED ->
                if (deletions.none { it.phase == DurableMutationPhase.COMMITTED }) {
                    impossibleState()
                }
            else -> Unit
        }
    }

    private fun validatePhase(mutation: DurableMutationRecord, keyState: KeyState) {
        when (mutation.phase) {
            DurableMutationPhase.PREPARED ->
                when (mutation.kind) {
                    DurableMutationKind.GENERATE ->
                        if (keyState != KeyState.CREATING) impossibleState()
                    DurableMutationKind.DELETE ->
                        if (keyState != KeyState.DELETE_PENDING) impossibleState()
                }
            DurableMutationPhase.COMMITTED ->
                when (mutation.kind) {
                    DurableMutationKind.GENERATE ->
                        if (keyState == KeyState.CREATING || keyState == KeyState.ABSENT) {
                            impossibleState()
                        }
                    DurableMutationKind.DELETE ->
                        if (keyState != KeyState.DELETED && keyState != KeyState.QUARANTINED) {
                            impossibleState()
                        }
                }
            DurableMutationPhase.QUARANTINED ->
                if (keyState != KeyState.QUARANTINED) impossibleState()
        }
    }

    private data class MutationIdentity(
        val scope: HandleScope,
        val kind: DurableMutationKind,
        val id: UUID,
    )

    private data class LogicalIdentity(val scope: HandleScope, val logicalNameHash: List<Byte>)
}

internal object DonorStateLimits {
    const val HASH_BYTES = 32
    const val MAX_RECORDS = 65_535
    const val MAX_SCOPE_STRING_BYTES = 1024
    const val MAX_ALIAS_BYTES = 255
    const val MAX_CHALLENGE_BYTES = 128
    const val MAX_PUBLIC_KEY_BYTES = 64 * 1024
    const val MAX_CERTIFICATE_BYTES = 256 * 1024
    const val MAX_CERTIFICATES = 16
}

internal fun requireFixedKeySpec(spec: WireKeySpec) {
    if (
        spec.algorithm != WireKeyAlgorithm.EC ||
            spec.curve != WireEcCurve.P256 ||
            spec.digest != WireDigest.SHA256 ||
            spec.purpose != WireKeyPurpose.SIGN
    ) {
        invalidRecord()
    }
}

internal fun WireKeyMetadata.defensiveCopy() =
    WireKeyMetadata(state, attestationChallenge, publicKey, certificateChain, keySpec)

private fun WireKeyMetadata.validatedCopy(): WireKeyMetadata {
    requireFixedKeySpec(keySpec)
    attestationChallenge.validBytes(1, DonorStateLimits.MAX_CHALLENGE_BYTES)
    publicKey.validBytes(1, DonorStateLimits.MAX_PUBLIC_KEY_BYTES)
    if (certificateChain.isEmpty() || certificateChain.size > DonorStateLimits.MAX_CERTIFICATES) {
        invalidRecord()
    }
    certificateChain.forEach { it.validBytes(1, DonorStateLimits.MAX_CERTIFICATE_BYTES) }
    return defensiveCopy()
}

private fun GenerateIntent.defensiveCopy() = GenerateIntent(logicalNameHash, challenge, keySpec)

private fun HandleScope.stableCopy() = HandleScope(pair, caller)

private fun validateScope(scope: HandleScope) {
    scope.canonicalFields().forEach { bytes ->
        if (bytes.isEmpty() || bytes.size > DonorStateLimits.MAX_SCOPE_STRING_BYTES) invalidRecord()
    }
    requireValidString(scope.pair.targetPin, DonorStateLimits.MAX_SCOPE_STRING_BYTES, true)
    requireValidString(scope.pair.donorPin, DonorStateLimits.MAX_SCOPE_STRING_BYTES, true)
    requireValidString(
        scope.caller.signingCertificateDigest,
        DonorStateLimits.MAX_SCOPE_STRING_BYTES,
        true,
    )
    requireValidString(
        scope.caller.attestationApplicationIdDigest,
        DonorStateLimits.MAX_SCOPE_STRING_BYTES,
        true,
    )
}

private fun requireValidString(value: String, maximumBytes: Int, requireNonBlank: Boolean) {
    if (requireNonBlank && value.isBlank()) invalidRecord()
    val encoder =
        StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
    val size =
        runCatching { encoder.encode(CharBuffer.wrap(value)).remaining() }
            .getOrElse { invalidRecord() }
    if (size > maximumBytes) invalidRecord()
}

private fun ByteArray.validFixedHash(): ByteArray =
    if (size == DonorStateLimits.HASH_BYTES) copyOf() else invalidRecord()

private fun ByteArray.validBytes(minimum: Int, maximum: Int): ByteArray =
    if (size in minimum..maximum) copyOf() else invalidRecord()

private fun invalidRecord(): Nothing = throw DonorStateQuarantineException.InvalidRecord()

private fun impossibleState(): Nothing = throw DonorStateQuarantineException.ImpossibleState()
