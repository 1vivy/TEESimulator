package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.EcCurve
import android.system.keystore2.Domain
import android.system.keystore2.KeyDescriptor
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import org.matrix.TEESimulator.attestation.KeyMintAttestation

internal data class CandidateGenerateParcel(
    val descriptor: KeyDescriptor,
    val attestation: KeyMintAttestation,
)

internal object CandidateKeyMintParcelCodec {
    private const val MAGIC = 0x434b4d31
    private const val VERSION = 1
    private const val MAX_ALIAS_BYTES = 255
    private const val MAX_CHALLENGE_BYTES = 128 * 1024
    private const val MAX_SET_VALUES = 8

    fun encodeGenerate(descriptor: KeyDescriptor, parsed: KeyMintAttestation): ByteArray {
        require(descriptor.domain == Domain.APP)
        val alias = requireNotNull(descriptor.alias).toByteArray(Charsets.UTF_8)
        val challenge = requireNotNull(parsed.attestationChallenge)
        require(alias.size in 1..MAX_ALIAS_BYTES && 0.toByte() !in alias)
        require(challenge.size in 1..MAX_CHALLENGE_BYTES)
        require(parsed.purpose.size <= MAX_SET_VALUES && parsed.digest.size <= MAX_SET_VALUES)
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.writeInt(MAGIC)
                out.writeByte(VERSION)
                out.writeInt(descriptor.domain)
                out.writeLong(descriptor.nspace)
                out.writeByte(alias.size)
                out.write(alias)
                out.writeInt(parsed.keySize)
                out.writeInt(parsed.algorithm)
                out.writeInt(parsed.ecCurve ?: -1)
                out.writeByte(parsed.purpose.size)
                parsed.purpose.forEach(out::writeInt)
                out.writeByte(parsed.digest.size)
                parsed.digest.forEach(out::writeInt)
                out.writeInt(challenge.size)
                out.write(challenge)
            }
            bytes.toByteArray()
        }
    }

    fun decodeGenerate(raw: ByteArray): CandidateGenerateParcel =
        DataInputStream(ByteArrayInputStream(raw)).use { input ->
            require(input.readInt() == MAGIC && input.readUnsignedByte() == VERSION)
            val domain = input.readInt()
            require(domain == Domain.APP)
            val namespace = input.readLong()
            val aliasLength = input.readUnsignedByte()
            require(aliasLength in 1..MAX_ALIAS_BYTES)
            val aliasBytes = ByteArray(aliasLength).also(input::readFully)
            require(0.toByte() !in aliasBytes)
            val alias = aliasBytes.toString(Charsets.UTF_8)
            require(alias.toByteArray(Charsets.UTF_8).contentEquals(aliasBytes))
            val keySize = input.readInt()
            val algorithm = input.readInt()
            val curve = input.readInt()
            val purposes = readValues(input)
            val digests = readValues(input)
            val challengeLength = input.readInt()
            require(challengeLength in 1..MAX_CHALLENGE_BYTES)
            val challenge = ByteArray(challengeLength).also(input::readFully)
            require(input.available() == 0)
            CandidateGenerateParcel(
                KeyDescriptor().apply {
                    this.domain = domain
                    nspace = namespace
                    this.alias = alias
                    blob = null
                },
                attestation(keySize, algorithm, curve, purposes, digests, challenge),
            )
        }

    private fun readValues(input: DataInputStream): List<Int> {
        val count = input.readUnsignedByte()
        require(count <= MAX_SET_VALUES)
        return List(count) { input.readInt() }
    }

    private fun attestation(
        keySize: Int,
        algorithm: Int,
        curve: Int,
        purposes: List<Int>,
        digests: List<Int>,
        challenge: ByteArray,
    ) =
        KeyMintAttestation(
            keySize = keySize,
            algorithm = algorithm,
            ecCurve = curve.takeUnless { it == -1 },
            ecCurveName = if (curve == EcCurve.P_256) "secp256r1" else "unknown",
            origin = null,
            blockMode = emptyList(),
            padding = emptyList(),
            purpose = purposes,
            digest = digests,
            rsaPublicExponent = null,
            certificateSerial = null,
            certificateSubject = null,
            certificateNotBefore = null,
            certificateNotAfter = null,
            attestationChallenge = challenge,
            brand = null,
            device = null,
            product = null,
            serial = null,
            imei = null,
            meid = null,
            manufacturer = null,
            model = null,
            secondImei = null,
            activeDateTime = null,
            originationExpireDateTime = null,
            usageExpireDateTime = null,
            usageCountLimit = null,
            callerNonce = null,
            nonce = null,
            unlockedDeviceRequired = null,
            includeUniqueId = null,
            rollbackResistance = null,
            earlyBootOnly = null,
            allowWhileOnBody = null,
            trustedUserPresenceRequired = null,
            trustedConfirmationRequired = null,
            noAuthRequired = null,
            maxUsesPerBoot = null,
            maxBootLevel = null,
            minMacLength = null,
            macLength = null,
            rsaOaepMgfDigest = emptyList(),
        )
}
