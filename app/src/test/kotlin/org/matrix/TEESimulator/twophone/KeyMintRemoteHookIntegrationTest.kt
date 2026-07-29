package org.matrix.TEESimulator.twophone

import android.content.pm.IPackageManager
import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.os.Parcelable
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.lang.reflect.Proxy
import java.security.Signature
import java.security.cert.CertificateFactory
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.config.CustomPatchLevel
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfile
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfileSource
import org.matrix.TEESimulator.interception.policy.FixtureInterceptionPolicy
import org.matrix.TEESimulator.interception.policy.FixturePackageResolver
import org.matrix.TEESimulator.interception.policy.InstalledFixturePackage
import org.matrix.TEESimulator.interception.policy.SigningCertificateDigest

class KeyMintRemoteHookIntegrationTest {
    @Test
    fun onPreTransactEncodesSelectedGenerateAndCreateIntoRemoteLifecycle() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        val packageManagerField =
            ConfigurationManager::class.java.getDeclaredField("iPackageManager").apply {
                isAccessible = true
            }
        val modesField =
            ConfigurationManager::class.java.getDeclaredField("packageModes").apply {
                isAccessible = true
            }
        val patchField =
            ConfigurationManager::class.java.getDeclaredField("globalCustomPatchLevel").apply {
                isAccessible = true
            }
        val cacheField =
            ConfigurationManager::class.java.getDeclaredField("uidToPackagesCache").apply {
                isAccessible = true
            }
        val originalPackageManager = packageManagerField.get(ConfigurationManager)
        val originalModes = modesField.get(ConfigurationManager)
        val originalPatch = patchField.get(ConfigurationManager)
        val cache = cacheField.get(ConfigurationManager) as MutableMap<*, *>
        val uid = 32123
        try {
            packageManagerField.set(ConfigurationManager, packageManager("org.example.fixture"))
            modesField.set(
                ConfigurationManager,
                mapOf("org.example.fixture" to ConfigurationManager.Mode.GENERATE),
            )
            patchField.set(ConfigurationManager, CustomPatchLevel(null, null, null, "2026-07-01"))
            cache.clear()
            val interceptor = interceptor(RemoteNormalizedKeyLifecycle(manager))
            val generateResult =
                interceptor.onPreTransact(
                    txId = 1,
                    target = interfaceProxy(IBinder::class.java),
                    code = transactionCode("generateKey"),
                    flags = 0,
                    callingUid = uid,
                    callingPid = 444,
                    data = encodedGenerateParcel("selected-key"),
                )
            val metadata =
                replyObject(
                    assertIs<BinderInterceptor.TransactionResult.OverrideReply>(generateResult)
                        .reply,
                    KeyMetadata.CREATOR,
                )
            val originDeathLease = FakeOriginProcessDeathLease()
            val createResult =
                interceptor.onPreTransactWithOriginDeath(
                    txId = 2,
                    target = interfaceProxy(IBinder::class.java),
                    code = transactionCode("createOperation"),
                    flags = 0,
                    callingUid = uid,
                    callingPid = 444,
                    data = encodedCreateParcel(metadata.key!!),
                    originDeathLease = originDeathLease,
                )
            val operation =
                replyObject(
                        assertIs<BinderInterceptor.TransactionResult.OverrideReply>(createResult)
                            .reply,
                        CreateOperationResponse.CREATOR,
                    )
                    .iOperation!!
            val first = "first-".encodeToByteArray()
            val second = "second".encodeToByteArray()
            operation.update(first)
            operation.update(second)
            val signature = operation.finish(ByteArray(0), null)
            assertTrue(originDeathLease.watchClosed.get())

            val publicKey =
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(metadata.certificate))
                    .publicKey
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(first)
                update(second)
                assertTrue(verify(signature))
            }
        } finally {
            packageManagerField.set(ConfigurationManager, originalPackageManager)
            modesField.set(ConfigurationManager, originalModes)
            patchField.set(ConfigurationManager, originalPatch)
            cache.clear()
            KeyMintSecurityLevelInterceptor.clearAllGeneratedKeys("host test cleanup")
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

    private fun encodedGenerateParcel(alias: String): Parcel =
        Parcel.obtain().apply {
            writeInterfaceToken(IKeystoreSecurityLevel.DESCRIPTOR)
            writeTypedObject(KeyDescriptor().apply { this.alias = alias }, 0)
            writeTypedObject(null, 0)
            writeTypedArray(signParameters(byteArrayOf(4, 5, 6)), 0)
            setDataPosition(0)
        }

    private fun encodedCreateParcel(key: KeyDescriptor): Parcel =
        Parcel.obtain().apply {
            writeInterfaceToken(IKeystoreSecurityLevel.DESCRIPTOR)
            writeTypedObject(key, 0)
            writeTypedArray(signParameters(ByteArray(0)), 0)
            writeBoolean(false)
            setDataPosition(0)
        }

    private fun signParameters(challenge: ByteArray): Array<KeyParameter> =
        listOf(
                parameter(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.EC)),
                parameter(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256)),
                parameter(Tag.DIGEST, KeyParameterValue.digest(Digest.SHA_2_256)),
                parameter(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.SIGN)),
            )
            .let { parameters ->
                if (challenge.isEmpty()) parameters
                else
                    parameters +
                        parameter(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(challenge))
            }
            .toTypedArray()

    private fun parameter(tag: Int, value: KeyParameterValue) =
        KeyParameter().apply {
            this.tag = tag
            this.value = value
        }

    private fun <T> replyObject(reply: Parcel, creator: Parcelable.Creator<T>): T {
        reply.setDataPosition(0)
        reply.readException()
        return checkNotNull(reply.readTypedObject(creator))
    }

    private fun transactionCode(method: String): Int =
        InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, method)

    private fun packageManager(packageName: String): IPackageManager =
        interfaceProxy(IPackageManager::class.java, packageName)

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
