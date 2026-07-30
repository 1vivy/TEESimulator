package org.matrix.teesimulator.rkafixture

enum class CandidateIdentityOwner {
    ROOT_DAEMON,
    CANDIDATE_COMPANION,
}

enum class CandidateGateState {
    IDENTITY_CREATED,
    PUBLIC_TRUST_STAGED,
    PROFILE_STAGED,
    LISTENER_READY,
    TLS_PROVED,
    ACTIVE,
}

data class CandidateOwnerProof(
    val owner: CandidateIdentityOwner,
    val states: List<CandidateGateState>,
    val privateKeyEncodedNull: Boolean,
    val insideSecurityHardware: Boolean,
    val teeSecurityLevel: Boolean,
    val ecP256: Boolean,
    val tlsProtocol: String,
    val clientCertificateRequired: Boolean,
    val pinnedPeer: Boolean,
    val interceptorReentryCount: Int,
    val candidateLocalGenerateCount: Int,
    val watchdogLatencyMillis: Long,
    val watchdogLimitMillis: Long,
    val rebootReceipt: Boolean,
    val failureCause: String? = null,
) {
    fun isProven(): Boolean =
        failureCause == null &&
            states == CandidateIdentityGate.requiredStates &&
            privateKeyEncodedNull &&
            insideSecurityHardware &&
            teeSecurityLevel &&
            ecP256 &&
            tlsProtocol == "TLSv1.3" &&
            clientCertificateRequired &&
            pinnedPeer &&
            interceptorReentryCount == 0 &&
            candidateLocalGenerateCount in 0..1 &&
            watchdogLatencyMillis in 0 until watchdogLimitMillis &&
            rebootReceipt
}

data class CandidateGateDecision(
    val proven: Boolean,
    val selectedOwner: String?,
    val errorCode: String?,
    val failureCauses: List<String>,
    val task6Marker: Boolean = false,
)

object CandidateIdentityGate {
    internal val requiredStates = CandidateGateState.entries

    @JvmStatic fun requiredStateNames(): List<String> = requiredStates.map { it.name }

    fun evaluate(
        root: CandidateOwnerProof,
        companion: () -> CandidateOwnerProof,
    ): CandidateGateDecision {
        require(root.owner == CandidateIdentityOwner.ROOT_DAEMON)
        if (root.isProven()) return root.toDecision()

        val fallback = companion()
        require(fallback.owner == CandidateIdentityOwner.CANDIDATE_COMPANION)
        if (fallback.isProven()) return fallback.toDecision()

        return CandidateGateDecision(
            proven = false,
            selectedOwner = null,
            errorCode = "CANDIDATE_TLS_OWNER_UNPROVEN",
            failureCauses = listOf(root.typedFailure(), fallback.typedFailure()),
        )
    }

    @JvmStatic
    fun evaluateInjected(
        rootProven: Boolean,
        rootFailure: String,
        companionProven: Boolean,
        companionFailure: String,
    ): CandidateGateDecision =
        evaluate(injectedProof(CandidateIdentityOwner.ROOT_DAEMON, rootProven, rootFailure)) {
            injectedProof(
                CandidateIdentityOwner.CANDIDATE_COMPANION,
                companionProven,
                companionFailure,
            )
        }

    private fun injectedProof(
        owner: CandidateIdentityOwner,
        proven: Boolean,
        failure: String,
    ): CandidateOwnerProof =
        CandidateOwnerProof(
            owner = owner,
            states = if (proven) requiredStates else emptyList(),
            privateKeyEncodedNull = proven,
            insideSecurityHardware = proven,
            teeSecurityLevel = proven,
            ecP256 = proven,
            tlsProtocol = if (proven) "TLSv1.3" else "",
            clientCertificateRequired = proven,
            pinnedPeer = proven,
            interceptorReentryCount = if (proven) 0 else 1,
            candidateLocalGenerateCount = if (proven) 1 else 0,
            watchdogLatencyMillis = if (proven) 1 else 30_000,
            watchdogLimitMillis = 30_000,
            rebootReceipt = proven,
            failureCause = if (proven) null else failure,
        )

    private fun CandidateOwnerProof.toDecision() =
        CandidateGateDecision(
            proven = true,
            selectedOwner = owner.name,
            errorCode = null,
            failureCauses = emptyList(),
        )

    private fun CandidateOwnerProof.typedFailure(): String =
        "${owner.name}:${failureCause ?: "ASSERTION_FAILED"}"
}

class ClientOwnedCandidateSession(private val closeAction: () -> Unit) {
    private var closed = false
    var deathLinked: Boolean = false
        private set

    val closeCount: Int
        get() = if (closed) 1 else 0

    fun linkToClientDeath() {
        check(!deathLinked)
        deathLinked = true
    }

    fun clientDied() = closeExactlyOnce()

    fun close() = closeExactlyOnce()

    private fun closeExactlyOnce() {
        if (closed) return
        closed = true
        closeAction()
    }
}
