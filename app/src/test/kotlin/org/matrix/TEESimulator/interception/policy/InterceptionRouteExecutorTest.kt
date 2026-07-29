package org.matrix.TEESimulator.interception.policy

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class InterceptionRouteExecutorTest {
    private val fixture = PolicyTestFixture()

    @Test
    fun exactFixtureRequestSelectsRemote() {
        val remoteReply = byteArrayOf(9, 8, 7)
        val executor = InterceptionRouteExecutor(fixture.policy) { remoteReply }

        val result = executor.execute(fixture.validRequest, byteArrayOf(1, 2, 3))

        assertSame(remoteReply, result)
        assertEquals(1, executor.remoteCallCount)
        assertEquals(0, executor.platformContinuationCount)
    }

    @Test
    fun nonMatchingRepliesAreExactPlatformObjectsWithoutRemoteCall() {
        var remoteCalls = 0
        val executor =
            InterceptionRouteExecutor(fixture.policy) {
                remoteCalls++
                byteArrayOf(9)
            }
        val failures =
            listOf(
                fixture.validRequest.copy(callingUid = 0),
                fixture.validRequest.copy(securityLevel = PolicySecurityLevel.STRONGBOX),
                fixture.validRequest.copy(algorithm = PolicyKeyAlgorithm.RSA),
                fixture.validRequest.copy(curve = PolicyEcCurve.P384),
                fixture.validRequest.copy(digests = setOf(PolicyDigest.SHA512)),
                fixture.validRequest.copy(purposes = setOf(PolicyPurpose.VERIFY)),
                fixture.validRequest.copy(callingUid = 88_888),
            )

        failures.forEachIndexed { index, request ->
            val platformResult = byteArrayOf(index.toByte(), 0x55)
            val result = executor.execute(request, platformResult)
            assertSame(platformResult, result)
            assertContentEquals(platformResult, result)
        }
        assertEquals(0, remoteCalls)
        assertEquals(0, executor.remoteCallCount)
        assertEquals(failures.size, executor.platformContinuationCount)
    }

    @Test
    fun uidZeroPolicyHarnessDoesNotInvokeSyntheticRemoteCallback() {
        var hookEntryCount = 0
        var callbackCount = 0
        var currentDepth = 0
        var maximumDepth = 0
        lateinit var activeHook: (InterceptionRequest, ByteArray) -> ByteArray
        val executor =
            InterceptionRouteExecutor(fixture.policy) { request ->
                callbackCount++
                activeHook(request.copy(callingUid = 0), byteArrayOf(4, 2))
            }
        activeHook = { request, platformReply ->
            hookEntryCount++
            currentDepth++
            maximumDepth = maxOf(maximumDepth, currentDepth)
            try {
                executor.execute(request, platformReply)
            } finally {
                currentDepth--
            }
        }
        val platformReply = byteArrayOf(4, 2)

        val result = activeHook(fixture.validRequest.copy(callingUid = 0), platformReply)

        assertSame(platformReply, result)
        assertEquals(1, hookEntryCount)
        assertEquals(1, maximumDepth)
        assertEquals(0, callbackCount)
        assertEquals(0, executor.remoteCallCount)
    }

    @Test
    fun remoteFailureNeverFallsBackToPlatform() {
        val executor =
            InterceptionRouteExecutor(fixture.policy) { throw RemoteFailure("synthetic") }

        assertFailsWith<RemoteFailure> {
            executor.execute(fixture.validRequest, byteArrayOf(1, 2, 3))
        }
        assertEquals(1, executor.remoteCallCount)
        assertEquals(0, executor.platformContinuationCount)
    }

    private class RemoteFailure(message: String) : RuntimeException(message)
}

private class PolicyTestFixture {
    private val signer = SigningCertificateDigest.parse("11".repeat(32))
    private val profile = ApprovedFixtureProfile("org.matrix.teesimulator.fixture", 42, signer)
    private val installed =
        InstalledFixturePackage(
            FIXTURE_UID,
            profile.packageName,
            profile.versionCode,
            setOf(signer),
        )

    val policy =
        FixtureInterceptionPolicy(
            ApprovedFixtureProfileSource { profile },
            FixturePackageResolver { uid, packageName ->
                installed.takeIf { uid == FIXTURE_UID && packageName == profile.packageName }
            },
            TARGET_DAEMON_PID,
        )

    val validRequest =
        InterceptionRequest(
            FIXTURE_UID,
            444,
            InterceptionMethod.CREATE_OPERATION,
            PolicySecurityLevel.TRUSTED_ENVIRONMENT,
            PolicyKeyAlgorithm.EC,
            PolicyEcCurve.P256,
            setOf(PolicyDigest.SHA256),
            setOf(PolicyPurpose.SIGN),
        )

    private companion object {
        const val FIXTURE_UID = 10_321
        const val TARGET_DAEMON_PID = 222
    }
}
