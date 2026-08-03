package org.matrix.TEESimulator.rka.donor

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.AttestationKey
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.IKeyMintDevice
import android.hardware.security.keymint.IKeyMintOperation
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicReference
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.broker.KeyMintClient

internal class AndroidDonorKeyMintDevice
private constructor(private val service: IKeyMintDevice, binder: IBinder) : DonorKeyMintDevice {
    private val deathCallback = AtomicReference<() -> Unit>({})

    init {
        check(binder.interfaceDescriptor == IKeyMintDevice.DESCRIPTOR)
        check(service.hardwareInfo.securityLevel == SecurityLevel.TRUSTED_ENVIRONMENT)
        binder.linkToDeath({ deathCallback.get().invoke() }, 0)
    }

    fun onDeath(callback: () -> Unit) {
        deathCallback.set(callback)
    }

    override fun generate(
        parameters: DonorKeyParameters,
        attestationKey: DonorAttestationKey,
    ): DonorKeyCreation {
        check(
            parameters.securityLevel == DonorSecurityLevel.TEE &&
                parameters.algorithm == DonorAlgorithm.EC &&
                parameters.curve == DonorCurve.P256 &&
                parameters.purpose == DonorPurpose.SIGN &&
                parameters.digest == DonorDigest.SHA256 &&
                parameters.noAuthRequired
        )
        val aidlAttestationKey =
            AttestationKey().apply {
                attestationKey.withBlob { keyBlob = it.copyOf() }
                issuerSubjectName = attestationKey.issuerSubjectName.copyOf()
                attestKeyParams = emptyArray()
            }
        val now = System.currentTimeMillis()
        val result =
            service.generateKey(
                arrayOf(
                    parameter(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.EC)),
                    parameter(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256)),
                    parameter(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.SIGN)),
                    parameter(Tag.DIGEST, KeyParameterValue.digest(Digest.SHA_2_256)),
                    parameter(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)),
                    parameter(
                        Tag.ATTESTATION_CHALLENGE,
                        KeyParameterValue.blob(parameters.challenge.copyOf()),
                    ),
                    parameter(
                        Tag.ATTESTATION_APPLICATION_ID,
                        KeyParameterValue.blob(parameters.aaid.copyOf()),
                    ),
                    parameter(
                        Tag.CERTIFICATE_NOT_BEFORE,
                        KeyParameterValue.dateTime(now - 60_000L),
                    ),
                    parameter(Tag.CERTIFICATE_NOT_AFTER, KeyParameterValue.dateTime(now + 120_000L)),
                ),
                aidlAttestationKey,
            )
        return DonorKeyCreation(
            result.keyBlob.copyOf(),
            characteristics(result.keyCharacteristics),
            result.certificateChain.map { it.encodedCertificate.copyOf() },
        )
    }

    override fun begin(keyBlob: ByteArray): DonorOperationEndpoint {
        val result =
            service.begin(
                KeyPurpose.SIGN,
                keyBlob,
                arrayOf(parameter(Tag.DIGEST, KeyParameterValue.digest(Digest.SHA_2_256))),
                null,
            )
        return AndroidDonorOperation(requireNotNull(result.operation))
    }

    override fun delete(keyBlob: ByteArray) {
        service.deleteKey(keyBlob)
    }

    private fun characteristics(
        values: Array<android.hardware.security.keymint.KeyCharacteristics>
    ): DonorKeyCharacteristics {
        val tee =
            values.singleOrNull { it.securityLevel == SecurityLevel.TRUSTED_ENVIRONMENT }
                ?: throw IllegalArgumentException("missing TEE characteristics")
        val authorizations = tee.authorizations.toList()
        require(
            authorizations.singleValue(Tag.ALGORITHM) { it.algorithm } == Algorithm.EC &&
                authorizations.singleValue(Tag.EC_CURVE) { it.ecCurve } == EcCurve.P_256 &&
                authorizations.values(Tag.PURPOSE) { it.keyPurpose } == setOf(KeyPurpose.SIGN) &&
                authorizations.values(Tag.DIGEST) { it.digest } == setOf(Digest.SHA_2_256) &&
                authorizations.singleValue(Tag.ORIGIN) { it.origin } == KeyOrigin.GENERATED &&
                authorizations.singleValue(Tag.NO_AUTH_REQUIRED) { it.boolValue }
        )
        return DonorKeyCharacteristics.exact()
    }

    private fun parameter(tag: Int, value: KeyParameterValue): KeyParameter =
        KeyParameter().apply {
            this.tag = tag
            this.value = value
        }

    private fun <T> List<KeyParameter>.singleValue(tag: Int, value: (KeyParameterValue) -> T): T =
        value(single { it.tag == tag }.value)

    private fun <T> List<KeyParameter>.values(tag: Int, value: (KeyParameterValue) -> T): Set<T> =
        filter { it.tag == tag }.map { value(it.value) }.toSet()

    companion object {
        fun resolve(): AndroidDonorKeyMintDevice {
            val binder =
                ServiceManager.checkService(KeyMintClient.DEFAULT_TEE_SERVICE)
                    ?: throw NoSuchElementException("TEE KeyMint unavailable")
            val service =
                IKeyMintDevice.Stub.asInterface(binder)
                    ?: throw NoSuchElementException("TEE KeyMint unavailable")
            return AndroidDonorKeyMintDevice(service, binder)
        }
    }
}

internal interface KeyMintOperationTransport {
    fun updateAad(input: ByteArray)

    fun finish(input: ByteArray): ByteArray

    fun abort()
}

private class BinderKeyMintOperationTransport(private val binder: IBinder) :
    KeyMintOperationTransport {
    override fun updateAad(input: ByteArray) {
        exchange(
            TRANSACTION_UPDATE_AAD,
            {
                it.writeByteArray(input)
                it.writeInt(0)
                it.writeInt(0)
            },
        ) {}
    }

    override fun finish(input: ByteArray): ByteArray =
        exchange(
            TRANSACTION_FINISH,
            {
                it.writeByteArray(input)
                it.writeByteArray(null)
                it.writeInt(0)
                it.writeInt(0)
                it.writeByteArray(null)
            },
        ) {
            requireNotNull(it.createByteArray())
        }

    override fun abort() {
        exchange(TRANSACTION_ABORT, {}) {}
    }

    private fun <T> exchange(code: Int, write: (Parcel) -> Unit, read: (Parcel) -> T): T {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(IKeyMintOperation.DESCRIPTOR)
            write(data)
            check(binder.transact(code, data, reply, 0))
            reply.readException()
            read(reply)
        } finally {
            reply.recycle()
            data.recycle()
        }
    }

    companion object {
        private const val TRANSACTION_UPDATE_AAD = IBinder.FIRST_CALL_TRANSACTION
        private const val TRANSACTION_FINISH = IBinder.FIRST_CALL_TRANSACTION + 2
        private const val TRANSACTION_ABORT = IBinder.FIRST_CALL_TRANSACTION + 3
    }
}

internal class AndroidDonorOperation
internal constructor(private val transport: KeyMintOperationTransport) : DonorOperationEndpoint {
    constructor(
        operation: IKeyMintOperation
    ) : this(BinderKeyMintOperationTransport(requireNotNull(operation.asBinder())))

    private val pendingInput = ByteArrayOutputStream()

    override fun updateAad(input: ByteArray) {
        transport.updateAad(input)
    }

    override fun update(input: ByteArray): ByteArray {
        require(input.size <= BridgeLimits.MAX_TOTAL_INPUT_BYTES - pendingInput.size())
        pendingInput.write(input)
        return ByteArray(0)
    }

    override fun finish(input: ByteArray): ByteArray {
        require(input.size <= BridgeLimits.MAX_TOTAL_INPUT_BYTES - pendingInput.size())
        val buffered = pendingInput.toByteArray()
        val complete = buffered + input
        return try {
            transport.finish(complete)
        } finally {
            buffered.fill(0)
            complete.fill(0)
            pendingInput.reset()
        }
    }

    override fun abort() {
        try {
            transport.abort()
        } finally {
            pendingInput.reset()
        }
    }
}
