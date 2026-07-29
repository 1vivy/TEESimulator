package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.interception.policy.AndroidFixturePackageResolver
import org.matrix.TEESimulator.interception.policy.ApprovedFixtureProfileSource
import org.matrix.TEESimulator.interception.policy.CallerDecision
import org.matrix.TEESimulator.interception.policy.FixtureInterceptionPolicy
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services. Only the TEE sub-service is eligible for interception; StrongBox remains entirely
 * on the platform path.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private val stubBinderClass = IKeystoreService.Stub::class.java
    @Volatile private var approvedProfileSource = ApprovedFixtureProfileSource { null }
    private val interceptionPolicy =
        FixtureInterceptionPolicy(
            approvedProfileSource = ApprovedFixtureProfileSource { approvedProfileSource.load() },
            packageResolver =
                AndroidFixturePackageResolver(ConfigurationManager::getPackageManager),
            targetDaemonPid = Process.myPid(),
        )

    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val LIST_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION =
        if (Build.VERSION.SDK_INT >= 34)
            InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched")
        else null

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the TEE
     * security-level sub-service. Deliberately excluded levels are never queried or registered.
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        interceptedSecurityLevels().forEach { securityLevel ->
            runCatching {
                    service.getSecurityLevel(securityLevel)?.let { keyMint ->
                        SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                        val interceptor =
                            KeyMintSecurityLevelInterceptor(
                                keyMint,
                                securityLevel,
                                interceptionPolicy,
                            )
                        register(
                            backdoor,
                            keyMint.asBinder(),
                            interceptor,
                            interceptor.originDeathTransactionCode,
                        )
                    }
                }
                .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }
        }
    }

    internal fun interceptedSecurityLevels(): List<Int> = listOf(SecurityLevel.TRUSTED_ENVIRONMENT)

    internal fun installApprovedFixtureProfileSource(source: ApprovedFixtureProfileSource) {
        approvedProfileSource = source
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (interceptionPolicy.beforeCaller(callingUid, callingPid) == CallerDecision.PLATFORM) {
            return TransactionResult.ContinueAndSkipPost
        }

        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)

            val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
            val isGMS = packages.contains("com.google.android.gms")

            if (isGMS || ConfigurationManager.shouldSkipUid(callingUid)) {
                return TransactionResult.ContinueAndSkipPost
            } else {
                return TransactionResult.Continue
            }
        } else if (
            code == GET_KEY_ENTRY_TRANSACTION ||
                code == DELETE_KEY_TRANSACTION ||
                code == UPDATE_SUBCOMPONENT_TRANSACTION
        ) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            if (ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost

            if (code == UPDATE_SUBCOMPONENT_TRANSACTION)
                return handleUpdateSubcomponent(callingUid, data)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost

            if (descriptor.alias != null) {
                SystemLogger.info("Handling ${transactionNames[code]!!} ${descriptor.alias}")
            } else {
                SystemLogger.info(
                    "Skip ${transactionNames[code]!!} for key [alias, blob, domain, nspace]: [${descriptor.alias}, ${descriptor.blob}, ${descriptor.domain}, ${descriptor.nspace}]"
                )
                return TransactionResult.ContinueAndSkipPost
            }
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            if (code == DELETE_KEY_TRANSACTION) {
                if (KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId) != null) {
                    KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                    SystemLogger.info(
                        "[TX_ID: $txId] Deleted cached keypair ${descriptor.alias}, replying with empty response."
                    )
                    return InterceptorUtils.createSuccessReply(writeResultCode = false)
                }
                return TransactionResult.ContinueAndSkipPost
            }

            val response =
                KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                    ?: return TransactionResult.Continue

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(it.keyParameter)
            }
            return InterceptorUtils.createTypedObjectReply(response)
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                true,
            )
        }

        // Let most calls go through to the real service.
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (target != keystoreService || reply == null) return TransactionResult.SkipTransaction

        if (code == GET_KEY_ENTRY_TRANSACTION) return TransactionResult.SkipTransaction

        if (InterceptorUtils.hasException(reply)) return TransactionResult.SkipTransaction

        if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            return runCatching {
                    val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                    val params =
                        ListEntriesHandler.cacheParameters(txId, data, isBatchMode)
                            ?: throw Exception("Abort updating entries for invalid parameters.")
                    val updatedKeyDescriptors =
                        ListEntriesHandler.injectGeneratedKeys(txId, callingUid, params, reply)
                    InterceptorUtils.createTypedArrayReply(updatedKeyDescriptors)
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to update the result of ${transactionNames[code]!!}.",
                        it,
                    )
                    TransactionResult.SkipTransaction
                }
        }
        return TransactionResult.SkipTransaction
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
        val generatedKeyInfo =
            KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(callingUid, descriptor?.nspace)
                ?: return TransactionResult.ContinueAndSkipPost

        SystemLogger.info("Updating sub-component with key[${generatedKeyInfo.nspace}]")
        val metadata = generatedKeyInfo.response.metadata
        val publicCert = data.createByteArray()
        val certificateChain = data.createByteArray()

        metadata.certificate = publicCert
        metadata.certificateChain = certificateChain
        SystemLogger.verbose(
            "Key updated with sizes: [publicCert, certificateChain] = [${publicCert?.size}, ${certificateChain?.size}]"
        )

        return InterceptorUtils.createSuccessReply(writeResultCode = false)
    }
}
