package org.matrix.teesimulator.physicalharness

import java.security.MessageDigest
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireKeyMetadata

internal sealed interface DurableKeyInspection {
    data object Absent : DurableKeyInspection

    class Verified(metadata: WireKeyMetadata) : DurableKeyInspection {
        private val stableMetadata = metadata.defensiveCopy()

        val metadata: WireKeyMetadata
            get() = stableMetadata.defensiveCopy()
    }

    data object Rejected : DurableKeyInspection
}

internal enum class DurableDeleteOutcome {
    ABSENT,
    DELETED,
    MISMATCH,
}

internal interface DurableAndroidKeyStore {
    fun ownedAliases(): Set<String>

    fun inspect(
        alias: String,
        caller: WireCallerIdentity,
        expectedChallenge: ByteArray?,
    ): DurableKeyInspection

    fun generate(alias: String, challenge: ByteArray, caller: WireCallerIdentity): WireKeyMetadata

    fun deleteIfExact(
        alias: String,
        caller: WireCallerIdentity,
        expectedMetadata: WireKeyMetadata,
    ): DurableDeleteOutcome
}

internal class AndroidKeystoreDurableKeyStore(private val donor: AndroidKeystoreDonor) :
    DurableAndroidKeyStore {
    override fun ownedAliases(): Set<String> = donor.ownedAliases()

    override fun inspect(
        alias: String,
        caller: WireCallerIdentity,
        expectedChallenge: ByteArray?,
    ): DurableKeyInspection = donor.inspect(alias, caller, expectedChallenge)

    override fun generate(
        alias: String,
        challenge: ByteArray,
        caller: WireCallerIdentity,
    ): WireKeyMetadata = donor.generate(alias, challenge, caller)

    override fun deleteIfExact(
        alias: String,
        caller: WireCallerIdentity,
        expectedMetadata: WireKeyMetadata,
    ): DurableDeleteOutcome = donor.deleteIfExact(alias, caller, expectedMetadata)
}

internal fun metadataMaterialEquals(left: WireKeyMetadata, right: WireKeyMetadata): Boolean {
    val challengeMatches =
        MessageDigest.isEqual(left.attestationChallenge, right.attestationChallenge)
    val publicKeyMatches = MessageDigest.isEqual(left.publicKey, right.publicKey)
    val leftCertificates = left.certificateChain
    val rightCertificates = right.certificateChain
    var certificatesMatch = leftCertificates.size == rightCertificates.size
    if (certificatesMatch) {
        leftCertificates.zip(rightCertificates).forEach { (leftCertificate, rightCertificate) ->
            certificatesMatch =
                certificatesMatch and MessageDigest.isEqual(leftCertificate, rightCertificate)
        }
    }
    val specificationMatches = left.keySpec == right.keySpec
    return challengeMatches and publicKeyMatches and certificatesMatch and specificationMatches
}
