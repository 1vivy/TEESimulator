package org.matrix.TEESimulator.interception.keystore

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.ServiceSpecificException
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import org.matrix.TEESimulator.rka.candidate.CandidateAlgorithm
import org.matrix.TEESimulator.rka.candidate.CandidateCharacteristics
import org.matrix.TEESimulator.rka.candidate.CandidateDigest
import org.matrix.TEESimulator.rka.candidate.CandidateError
import org.matrix.TEESimulator.rka.candidate.CandidateKeyRecord
import org.matrix.TEESimulator.rka.candidate.CandidatePurpose
import org.matrix.TEESimulator.rka.candidate.CandidateResult
import org.matrix.TEESimulator.rka.candidate.CandidateRuntime
import org.matrix.TEESimulator.rka.candidate.RemoteOperationHandle

internal object CandidateBinderAdapter {
    fun metadata(record: CandidateKeyRecord): KeyMetadata {
        val chain = record.certificateChain()
        return KeyMetadata().apply {
            key =
                KeyDescriptor().apply {
                    domain = Domain.KEY_ID
                    nspace = record.id.namespace
                    alias = null
                    blob = null
                }
            keySecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT
            certificate = chain.first().copyOf()
            certificateChain = chain.drop(1).fold(ByteArray(0)) { all, cert -> all + cert }
            authorizations = authorizations(record.characteristics)
        }
    }

    fun entry(record: CandidateKeyRecord, securityLevel: IKeystoreSecurityLevel?) =
        KeyEntryResponse().apply {
            metadata = metadata(record)
            iSecurityLevel = securityLevel
        }

    fun operation(runtime: CandidateRuntime, handle: RemoteOperationHandle) =
        CreateOperationResponse().apply {
            iOperation = RemoteCandidateOperationBinder(runtime, handle)
            operationChallenge = null
            parameters = null
        }

    fun errorCode(error: CandidateError): Int =
        when (error) {
            CandidateError.INVALID_REQUEST -> -38
            CandidateError.UNSUPPORTED_ALGORITHM -> -4
            CandidateError.UNSUPPORTED_PURPOSE -> -3
            CandidateError.UNSUPPORTED_DIGEST -> -12
            CandidateError.UNSUPPORTED_EC_CURVE -> -61
            CandidateError.POLICY_REJECTED,
            CandidateError.CROSS_UID_GRANT_UNSUPPORTED -> 6
            CandidateError.CAPACITY -> -29
            CandidateError.STALE_HANDLE -> 7
            CandidateError.TRANSPORT,
            CandidateError.OPERATION_LOST -> -49
            CandidateError.QUARANTINED -> 6
        }

    private fun authorizations(characteristics: CandidateCharacteristics): Array<Authorization> {
        val result = mutableListOf<Authorization>()
        fun add(tag: Int, value: KeyParameterValue) {
            result +=
                Authorization().apply {
                    securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT
                    keyParameter =
                        KeyParameter().apply {
                            this.tag = tag
                            this.value = value
                        }
                }
        }
        characteristics.purposes.forEach {
            add(
                Tag.PURPOSE,
                KeyParameterValue.keyPurpose(if (it == CandidatePurpose.SIGN) 2 else 3),
            )
        }
        add(
            Tag.ALGORITHM,
            KeyParameterValue.algorithm(
                if (characteristics.algorithm == CandidateAlgorithm.EC) Algorithm.EC
                else Algorithm.RSA
            ),
        )
        add(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256))
        characteristics.digests.forEach {
            add(
                Tag.DIGEST,
                KeyParameterValue.digest(
                    if (it == CandidateDigest.SHA256) Digest.SHA_2_256 else Digest.NONE
                ),
            )
        }
        return result.toTypedArray()
    }
}

internal class RemoteCandidateOperationBinder(
    private val runtime: CandidateRuntime,
    private val handle: RemoteOperationHandle,
) : IKeystoreOperation.Stub() {
    @Synchronized
    override fun updateAad(aadInput: ByteArray?) {
        runtime.updateAad(handle, aadInput?.copyOf() ?: ByteArray(0)).valueOrThrow()
    }

    @Synchronized
    override fun update(input: ByteArray?): ByteArray {
        runtime.update(handle, input?.copyOf() ?: ByteArray(0)).valueOrThrow()
        return ByteArray(0)
    }

    @Synchronized
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray =
        runtime.finish(handle, input?.copyOf() ?: ByteArray(0)).valueOrThrow()

    @Synchronized
    override fun abort() {
        runtime.abort(handle).valueOrThrow()
    }

    private fun <T> CandidateResult<T>.valueOrThrow(): T =
        when (this) {
            is CandidateResult.Success -> value
            is CandidateResult.Failure ->
                throw ServiceSpecificException(CandidateBinderAdapter.errorCode(error))
        }
}
