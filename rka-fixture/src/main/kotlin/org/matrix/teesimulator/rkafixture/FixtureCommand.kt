package org.matrix.teesimulator.rkafixture

enum class FixtureCommandCaller {
    SHELL,
    OTHER,
}

object FixtureNonce {
    const val BYTES = 16
}

object FixtureAttestationChallenge {
    const val BYTES = 32
}

object FixtureCommandAction {
    const val PROVISION = "org.matrix.teesimulator.rkafixture.v1.PROVISION"
    const val START = "org.matrix.teesimulator.rkafixture.v1.START"
    const val STATUS = "org.matrix.teesimulator.rkafixture.v1.STATUS"
    const val ATTEST_SIGN = "org.matrix.teesimulator.rkafixture.v1.ATTEST_SIGN"
    const val STOP = "org.matrix.teesimulator.rkafixture.v1.STOP"
}

class FixtureCommandInput(
    val caller: FixtureCommandCaller,
    val version: Int,
    val action: String?,
    nonce: ByteArray,
    challenge: ByteArray?,
    profile: ByteArray?,
    val profileId: String?,
    val metadata: String?,
    extraNames: Set<String>,
) {
    private val nonceBytes = nonce.copyOf()
    private val challengeBytes = challenge?.copyOf()
    private val profileBytes = profile?.copyOf()
    private val suppliedExtraNames = extraNames.toSet()

    val nonce: ByteArray
        get() = nonceBytes.copyOf()

    val challenge: ByteArray?
        get() = challengeBytes?.copyOf()

    val profile: ByteArray?
        get() = profileBytes?.copyOf()

    val extraNames: Set<String>
        get() = suppliedExtraNames
}

sealed class FixtureCommand(nonce: ByteArray, activeRoles: Set<String>) {
    private val nonceBytes = nonce.copyOf()
    private val roleNames = activeRoles.toSet()

    val nonce: ByteArray
        get() = nonceBytes.copyOf()

    val activeRoles: Set<String>
        get() = roleNames

    class Provision(nonce: ByteArray, activeRoles: Set<String>, profile: ByteArray) :
        FixtureCommand(nonce, activeRoles) {
        private val encodedProfile = profile.copyOf()

        val profile: ByteArray
            get() = encodedProfile.copyOf()
    }

    class Start(nonce: ByteArray, activeRoles: Set<String>, val profileId: String) :
        FixtureCommand(nonce, activeRoles)

    class Status(nonce: ByteArray, activeRoles: Set<String>) : FixtureCommand(nonce, activeRoles)

    class AttestSign(nonce: ByteArray, activeRoles: Set<String>, challenge: ByteArray) :
        FixtureCommand(nonce, activeRoles) {
        private val challengeBytes = challenge.copyOf()

        val challenge: ByteArray
            get() = challengeBytes.copyOf()
    }

    class Stop(nonce: ByteArray, activeRoles: Set<String>) : FixtureCommand(nonce, activeRoles)

    companion object {
        const val VERSION = 1
    }
}

sealed class FixtureCommandResult {
    data object Provisioned : FixtureCommandResult()

    data object Started : FixtureCommandResult()

    data object Status : FixtureCommandResult()

    data object Stopped : FixtureCommandResult()

    class AttestedSigned(val result: FixtureAttestationResult) : FixtureCommandResult()
}

enum class FixtureCommandErrorCode {
    UNAUTHORIZED_CALLER,
    UNSUPPORTED_VERSION,
    UNKNOWN_COMMAND,
    INVALID_FIELD,
    OVERSIZED_FIELD,
    REPLAYED_NONCE,
    FORBIDDEN_FIELD,
    INVALID_METADATA,
}

sealed class FixtureCommandError(val code: FixtureCommandErrorCode) :
    IllegalArgumentException(code.name) {
    data object UnauthorizedCaller :
        FixtureCommandError(FixtureCommandErrorCode.UNAUTHORIZED_CALLER)

    data object UnsupportedVersion :
        FixtureCommandError(FixtureCommandErrorCode.UNSUPPORTED_VERSION)

    data object UnknownCommand : FixtureCommandError(FixtureCommandErrorCode.UNKNOWN_COMMAND)

    class InvalidField(val field: String) :
        FixtureCommandError(FixtureCommandErrorCode.INVALID_FIELD)

    class OversizedField(val field: String) :
        FixtureCommandError(FixtureCommandErrorCode.OVERSIZED_FIELD)

    data object ReplayedNonce : FixtureCommandError(FixtureCommandErrorCode.REPLAYED_NONCE)

    class ForbiddenField(val field: String) :
        FixtureCommandError(FixtureCommandErrorCode.FORBIDDEN_FIELD)

    data object InvalidMetadata : FixtureCommandError(FixtureCommandErrorCode.INVALID_METADATA)
}
