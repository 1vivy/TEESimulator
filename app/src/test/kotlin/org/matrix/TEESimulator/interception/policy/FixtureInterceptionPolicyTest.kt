package org.matrix.TEESimulator.interception.policy

import kotlin.test.Test
import kotlin.test.assertEquals

class FixtureInterceptionPolicyTest {
    private val signer = SigningCertificateDigest.parse("11".repeat(32))
    private val profile =
        ApprovedFixtureProfile(
            packageName = "org.matrix.teesimulator.fixture",
            versionCode = 42,
            signerDigest = signer,
        )
    private val installed =
        InstalledFixturePackage(
            uid = FIXTURE_UID,
            packageName = profile.packageName,
            versionCode = profile.versionCode,
            signerDigests = setOf(signer),
        )

    @Test
    fun exactFixtureTeeEcP256Sha256SignRequestIsNonVacuouslyRemote() {
        val policy = policy()

        assertEquals(PreParcelDecision.DECODE_SUPPORTED_REQUEST, policy.beforeParcel(validRequest))
        assertEquals(InterceptionDecision.REMOTE, policy.decide(validRequest))
    }

    @Test
    fun exhaustiveFailureMatrixContinuesOnPlatform() {
        val otherSigner = SigningCertificateDigest.parse("22".repeat(32))
        val requests =
            listOf(
                validRequest.copy(callingUid = 0),
                validRequest.copy(callingPid = TARGET_DAEMON_PID),
                validRequest.copy(securityLevel = PolicySecurityLevel.STRONGBOX),
                validRequest.copy(securityLevel = PolicySecurityLevel.SOFTWARE),
                validRequest.copy(algorithm = PolicyKeyAlgorithm.RSA),
                validRequest.copy(curve = PolicyEcCurve.P384),
                validRequest.copy(digests = setOf(PolicyDigest.SHA512)),
                validRequest.copy(digests = setOf(PolicyDigest.SHA256, PolicyDigest.SHA512)),
                validRequest.copy(purposes = setOf(PolicyPurpose.VERIFY)),
                validRequest.copy(purposes = setOf(PolicyPurpose.SIGN, PolicyPurpose.VERIFY)),
                validRequest.copy(method = InterceptionMethod.IMPORT_KEY),
            )

        requests.forEach { request ->
            assertEquals(
                InterceptionDecision.PLATFORM,
                policy().decide(request),
                request.toString(),
            )
        }
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(resolved = null).decide(validRequest),
            "unknown package",
        )
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(resolved = installed.copy(versionCode = 43)).decide(validRequest),
            "mismatched version",
        )
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(resolved = installed.copy(signerDigests = setOf(otherSigner)))
                .decide(validRequest),
            "mismatched signer",
        )
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(approvedProfile = null).decide(validRequest),
            "missing approved profile",
        )
    }

    @Test
    fun hardExclusionsRunBeforePackageResolutionOrParcelDecoding() {
        var packageResolutionCount = 0
        val policy =
            FixtureInterceptionPolicy(
                approvedProfileSource = ApprovedFixtureProfileSource { profile },
                packageResolver =
                    FixturePackageResolver { _, _ ->
                        packageResolutionCount++
                        installed
                    },
                targetDaemonPid = TARGET_DAEMON_PID,
            )
        val excluded =
            listOf(
                validRequest.copy(callingUid = 0),
                validRequest.copy(callingPid = TARGET_DAEMON_PID),
                validRequest.copy(securityLevel = PolicySecurityLevel.STRONGBOX),
                validRequest.copy(method = InterceptionMethod.IMPORT_KEY),
            )

        excluded.forEach { request ->
            assertEquals(PreParcelDecision.PLATFORM, policy.beforeParcel(request))
        }
        assertEquals(0, packageResolutionCount)
    }

    @Test
    fun packageManagerIdentityMustMatchApprovedPackageUidVersionAndSigner() {
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(resolved = installed.copy(uid = FIXTURE_UID + 1)).decide(validRequest),
        )
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(resolved = installed.copy(packageName = "other.package")).decide(validRequest),
        )
        assertEquals(
            InterceptionDecision.PLATFORM,
            policy(
                    resolved =
                        installed.copy(
                            signerDigests =
                                setOf(signer, SigningCertificateDigest.parse("33".repeat(32)))
                        )
                )
                .decide(validRequest),
        )
    }

    private fun policy(
        approvedProfile: ApprovedFixtureProfile? = profile,
        resolved: InstalledFixturePackage? = installed,
    ) =
        FixtureInterceptionPolicy(
            approvedProfileSource = ApprovedFixtureProfileSource { approvedProfile },
            packageResolver = FixturePackageResolver { _, _ -> resolved },
            targetDaemonPid = TARGET_DAEMON_PID,
        )

    private val validRequest =
        InterceptionRequest(
            callingUid = FIXTURE_UID,
            callingPid = 444,
            method = InterceptionMethod.CREATE_OPERATION,
            securityLevel = PolicySecurityLevel.TRUSTED_ENVIRONMENT,
            algorithm = PolicyKeyAlgorithm.EC,
            curve = PolicyEcCurve.P256,
            digests = setOf(PolicyDigest.SHA256),
            purposes = setOf(PolicyPurpose.SIGN),
        )

    private companion object {
        const val FIXTURE_UID = 10_321
        const val TARGET_DAEMON_PID = 222
    }
}
