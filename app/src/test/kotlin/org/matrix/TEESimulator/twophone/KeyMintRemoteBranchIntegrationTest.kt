package org.matrix.TEESimulator.twophone

import android.hardware.security.keymint.SecurityLevel
import android.system.keystore2.IKeystoreSecurityLevel
import java.lang.reflect.Proxy
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfile
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfileSource
import org.matrix.TEESimulator.interception.policy.FixtureInterceptionPolicy
import org.matrix.TEESimulator.interception.policy.FixturePackageResolver
import org.matrix.TEESimulator.interception.policy.InstalledFixturePackage
import org.matrix.TEESimulator.interception.policy.InterceptionRequest
import org.matrix.TEESimulator.interception.policy.PolicyDigest
import org.matrix.TEESimulator.interception.policy.PolicyEcCurve
import org.matrix.TEESimulator.interception.policy.PolicyKeyAlgorithm
import org.matrix.TEESimulator.interception.policy.PolicyPurpose
import org.matrix.TEESimulator.interception.policy.PolicySecurityLevel
import org.matrix.TEESimulator.interception.policy.SigningCertificateDigest
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec
import org.matrix.teesimulator.twophone.WireOutcome

class KeyMintRemoteBranchIntegrationTest {
    @Test
    fun selectedInterceptorBranchGeneratesBeginsUpdatesAndFinishesWithRemoteEcdsaSignature() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        try {
            val interceptor = interceptor(RemoteNormalizedKeyLifecycle(manager))
            val generated =
                assertNotNull(
                    interceptor.generateSelectedRemoteKey(
                        remoteRequest(),
                        RemoteKeyGeneration("selected-key", byteArrayOf(4, 5, 6)),
                    )
                )
            val operation =
                assertNotNull(
                    interceptor.createSelectedRemoteOperation(
                        remoteRequest(),
                        generated,
                        FakeOriginProcessDeathLease(),
                    )
                )
            val first = "first-".encodeToByteArray()
            val second = "second".encodeToByteArray()

            operation.update(first)
            operation.update(second)
            val signature = operation.finish(ByteArray(0), null)

            val publicKey =
                KeyFactory.getInstance("EC")
                    .generatePublic(X509EncodedKeySpec(generated.metadata.publicKey))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(first)
                update(second)
                assertTrue(verify(signature))
            }
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    @Test
    fun selectedInterceptorBranchPropagatesRemoteFailureWithoutLocalOperationFallback() {
        val manager = managerWithBeginFailure()
        val interceptor = interceptor(RemoteNormalizedKeyLifecycle(manager))
        val remoteKey =
            RemoteGeneratedKey(
                manager,
                WireKeyHandle(java.util.UUID.randomUUID(), byteArrayOf(1)),
                remoteMetadata(),
            )

        assertFailsWith<TargetSessionException.RemoteFailure> {
            interceptor.createSelectedRemoteOperation(
                remoteRequest(),
                remoteKey,
                FakeOriginProcessDeathLease(),
            )
        }
    }

    @Test
    fun fixtureAttestKeyCreateOperationRemainsPlatformContinuationWithoutRemoteOperation() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        try {
            val lifecycle = RemoteNormalizedKeyLifecycle(manager)
            val generated = lifecycle.generate(RemoteKeyGeneration("selected-key", byteArrayOf(9)))
            val interceptor = interceptor(lifecycle)

            assertNull(
                interceptor.createSelectedRemoteOperation(
                    remoteRequest(purposes = setOf(PolicyPurpose.ATTEST_KEY)),
                    generated,
                    FakeOriginProcessDeathLease(),
                )
            )
            assertTrue(KeyMintSecurityLevelInterceptor.generatedKeys.isEmpty())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    private fun interceptor(lifecycle: RemoteNormalizedKeyLifecycle) =
        KeyMintSecurityLevelInterceptor(
            interfaceProxy(IKeystoreSecurityLevel::class.java),
            SecurityLevel.TRUSTED_ENVIRONMENT,
            policy(),
            remoteLifecycleFactory = { lifecycle },
        )

    private fun policy(): FixtureInterceptionPolicy {
        val signer = SigningCertificateDigest.parse("01".repeat(32))
        val profile = ApprovedFixtureProfile("org.example.fixture", 1, signer)
        return FixtureInterceptionPolicy(
            ApprovedFixtureProfileSource { profile },
            FixturePackageResolver { uid, packageName ->
                InstalledFixturePackage(uid, packageName, 1, setOf(signer))
            },
            targetDaemonPid = -1,
        )
    }

    private fun remoteRequest(purposes: Set<PolicyPurpose> = setOf(PolicyPurpose.SIGN)) =
        InterceptionRequest(
            callingUid = 32123,
            callingPid = 444,
            method =
                org.matrix.TEESimulator.interception.policy.InterceptionMethod.CREATE_OPERATION,
            securityLevel = PolicySecurityLevel.TRUSTED_ENVIRONMENT,
            algorithm = PolicyKeyAlgorithm.EC,
            curve = PolicyEcCurve.P256,
            digests = setOf(PolicyDigest.SHA256),
            purposes = purposes,
        )

    private fun managerWithBeginFailure(): TargetSessionManager {
        val rig = TargetLoopbackTestRig()
        return TargetSessionManager.createForTest(
            rig.profile,
            rig.caller,
            Instant::now,
            TargetConnectionFactory { _, _ ->
                object : TargetConnection {
                    override val protocol = "TLSv1.3"

                    override fun exchange(
                        sequence: ULong,
                        payload: org.matrix.teesimulator.twophone.LifecycleRequestPayload,
                        caller: org.matrix.teesimulator.twophone.WireCallerIdentity,
                        deadline: Instant,
                        cancellation: TargetCallCancellation,
                    ) = WireOutcome.Error(WireErrorCode.DONOR_UNAVAILABLE)

                    override fun close() = Unit
                }
            },
        )
    }

    private fun remoteMetadata() =
        WireKeyMetadata(
            org.matrix.teesimulator.twophone.KeyState.ACTIVE,
            byteArrayOf(1),
            byteArrayOf(2),
            listOf(byteArrayOf(3)),
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            ),
        )

    private fun <T> interfaceProxy(type: Class<T>, packageName: String? = null): T =
        checkNotNull(
            type.cast(
                Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ ->
                    when (method.name) {
                        "getPackagesForUid" -> arrayOf(packageName)
                        else ->
                            when (method.returnType) {
                                Boolean::class.javaPrimitiveType -> false
                                Int::class.javaPrimitiveType -> 0
                                Long::class.javaPrimitiveType -> 0L
                                else -> null
                            }
                    }
                }
            )
        )
}
