package org.matrix.TEESimulator.interception.policy

import java.security.MessageDigest
import java.util.Locale
import org.matrix.teesimulator.twophone.FixturePackageIdentity

@JvmInline
value class SigningCertificateDigest private constructor(val hex: String) {
    companion object {
        fun parse(value: String): SigningCertificateDigest {
            val normalized = value.lowercase(Locale.ROOT)
            require(
                normalized.length == SHA256_HEX_LENGTH &&
                    normalized.all { it in '0'..'9' || it in 'a'..'f' }
            ) {
                "signing certificate digest must be SHA-256"
            }
            return SigningCertificateDigest(normalized)
        }

        fun sha256(certificate: ByteArray): SigningCertificateDigest {
            val digest = MessageDigest.getInstance("SHA-256").digest(certificate)
            return SigningCertificateDigest(
                digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            )
        }

        private const val SHA256_HEX_LENGTH = 64
    }
}

data class ApprovedFixtureProfile(
    val packageName: String,
    val versionCode: Long,
    val signerDigest: SigningCertificateDigest,
) {
    init {
        require(packageName.isNotBlank()) { "fixture package name must not be blank" }
        require(versionCode >= 0) { "fixture version code must not be negative" }
    }
}

data class InstalledFixturePackage(
    val uid: Int,
    val packageName: String,
    val versionCode: Long,
    val signerDigests: Set<SigningCertificateDigest>,
)

fun interface ApprovedFixtureProfileSource {
    fun load(): ApprovedFixtureProfile?
}

fun interface FixturePackageResolver {
    fun resolve(uid: Int, packageName: String): InstalledFixturePackage?
}

enum class InterceptionMethod {
    GENERATE_KEY,
    CREATE_OPERATION,
    IMPORT_KEY,
    UPDATE,
    FINISH,
    ABORT,
    UNKNOWN,
}

enum class PolicySecurityLevel {
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    SOFTWARE,
    UNKNOWN,
}

enum class PolicyKeyAlgorithm {
    EC,
    RSA,
    UNKNOWN,
}

enum class PolicyEcCurve {
    P256,
    P384,
    P521,
    CURVE25519,
    UNKNOWN,
}

enum class PolicyDigest {
    SHA256,
    SHA512,
    NONE,
    UNKNOWN,
}

enum class PolicyPurpose {
    SIGN,
    VERIFY,
    ENCRYPT,
    DECRYPT,
    ATTEST_KEY,
    UNKNOWN,
}

data class InterceptionRequest(
    val callingUid: Int,
    val callingPid: Int,
    val method: InterceptionMethod,
    val securityLevel: PolicySecurityLevel,
    val algorithm: PolicyKeyAlgorithm = PolicyKeyAlgorithm.UNKNOWN,
    val curve: PolicyEcCurve = PolicyEcCurve.UNKNOWN,
    val digests: Set<PolicyDigest> = emptySet(),
    val purposes: Set<PolicyPurpose> = emptySet(),
)

enum class PreParcelDecision {
    DECODE_SUPPORTED_REQUEST,
    PLATFORM,
}

enum class CallerDecision {
    EVALUATE_METHOD,
    PLATFORM,
}

enum class InterceptionDecision {
    REMOTE,
    PLATFORM,
}

class FixtureInterceptionPolicy(
    private val approvedProfileSource: ApprovedFixtureProfileSource,
    private val packageResolver: FixturePackageResolver,
    private val targetDaemonPid: Int,
) {
    fun beforeCaller(callingUid: Int, callingPid: Int): CallerDecision =
        if (callingUid == ROOT_UID || callingPid == targetDaemonPid) {
            CallerDecision.PLATFORM
        } else {
            CallerDecision.EVALUATE_METHOD
        }

    fun beforeParcel(request: InterceptionRequest): PreParcelDecision {
        if (beforeCaller(request.callingUid, request.callingPid) == CallerDecision.PLATFORM) {
            return PreParcelDecision.PLATFORM
        }
        if (request.securityLevel != PolicySecurityLevel.TRUSTED_ENVIRONMENT) {
            return PreParcelDecision.PLATFORM
        }
        if (request.method !in supportedMethods) return PreParcelDecision.PLATFORM

        val profile = approvedProfileSource.load() ?: return PreParcelDecision.PLATFORM
        val installed =
            packageResolver.resolve(request.callingUid, profile.packageName)
                ?: return PreParcelDecision.PLATFORM
        if (!installed.matches(request.callingUid, profile)) return PreParcelDecision.PLATFORM

        return PreParcelDecision.DECODE_SUPPORTED_REQUEST
    }

    fun decide(request: InterceptionRequest): InterceptionDecision {
        if (beforeParcel(request) != PreParcelDecision.DECODE_SUPPORTED_REQUEST) {
            return InterceptionDecision.PLATFORM
        }
        if (request.algorithm != PolicyKeyAlgorithm.EC || request.curve != PolicyEcCurve.P256) {
            return InterceptionDecision.PLATFORM
        }
        if (request.digests != setOf(PolicyDigest.SHA256)) {
            return InterceptionDecision.PLATFORM
        }
        if (request.purposes != setOf(PolicyPurpose.SIGN)) {
            return InterceptionDecision.PLATFORM
        }
        return InterceptionDecision.REMOTE
    }

    fun remoteFixtureIdentity(request: InterceptionRequest): FixturePackageIdentity? {
        if (decide(request) != InterceptionDecision.REMOTE) return null
        val profile = approvedProfileSource.load() ?: return null
        return FixturePackageIdentity.create(
            profile.packageName,
            profile.versionCode,
            profile.signerDigest.hex.hexToByteArray(),
        )
    }

    private fun InstalledFixturePackage.matches(
        callingUid: Int,
        profile: ApprovedFixtureProfile,
    ): Boolean =
        uid == callingUid &&
            packageName == profile.packageName &&
            versionCode == profile.versionCode &&
            signerDigests == setOf(profile.signerDigest)

    private companion object {
        const val ROOT_UID = 0
        val supportedMethods =
            setOf(InterceptionMethod.GENERATE_KEY, InterceptionMethod.CREATE_OPERATION)
    }
}

private fun String.hexToByteArray(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
