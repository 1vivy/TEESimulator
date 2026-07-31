package org.matrix.TEESimulator.rka.trust

import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.system.exitProcess
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PacketTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider

internal data class AgentPgpAnchorInspection(
    val publicPrimaryKeys: Int,
    val publicSubkeys: Int,
    val userIds: Int,
    val userAttributes: Int,
    val secretKeys: Int,
    val signatures: Int,
    val otherPackets: Int,
)

object AgentPgpVerifier {
    private const val MAX_ANCHOR_BYTES = 8 * 1024
    private const val MAX_BUNDLE_BYTES = 4 * 1024
    private const val MAX_SIGNATURE_BYTES = 8 * 1024
    private const val HASH_LENGTH = 64
    private const val PINNED_ANCHOR_SHA256 =
        "db3d0beed0e376dc631b9c6c57ac1d610955e08b1734828ca1dd5d24ceeef4b1"
    private val lowerHex = Regex("[0-9a-f]{$HASH_LENGTH}")

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size != 5) exitProcess(2)
        val accepted =
            try {
                verify(
                    readBounded(Path.of(args[0]), MAX_ANCHOR_BYTES),
                    readBounded(Path.of(args[1]), MAX_BUNDLE_BYTES),
                    readBounded(Path.of(args[2]), MAX_SIGNATURE_BYTES),
                    args[3],
                    args[4],
                )
            } catch (_: IOException) {
                false
            } catch (_: IllegalArgumentException) {
                false
            } catch (_: SecurityException) {
                false
            }
        exitProcess(if (accepted) 0 else 1)
    }

    internal fun verify(
        anchor: ByteArray,
        bundle: ByteArray,
        detachedSignature: ByteArray,
        oldHash: String,
        newHash: String,
    ): Boolean {
        if (
            anchor.isEmpty() ||
                anchor.size > MAX_ANCHOR_BYTES ||
                bundle.isEmpty() ||
                bundle.size > MAX_BUNDLE_BYTES ||
                detachedSignature.isEmpty() ||
                detachedSignature.size > MAX_SIGNATURE_BYTES ||
                !lowerHex.matches(oldHash) ||
                !lowerHex.matches(newHash) ||
                oldHash == newHash
        ) {
            return false
        }
        return try {
            val expectedAnchorHash = hexBytes(PINNED_ANCHOR_SHA256)
            val actualAnchorHash = MessageDigest.getInstance("SHA-256").digest(anchor)
            if (!MessageDigest.isEqual(expectedAnchorHash, actualAnchorHash)) return false
            val inspection = inspectAnchor(anchor)
            if (
                inspection.publicPrimaryKeys != 1 ||
                    inspection.userIds != 0 ||
                    inspection.userAttributes != 0 ||
                    inspection.secretKeys != 0 ||
                    inspection.otherPackets != 0
            ) {
                return false
            }
            if (!authorizationMatches(bundle, oldHash, newHash)) return false
            val ring = PGPPublicKeyRing(anchor, BcKeyFingerprintCalculator())
            val signature = detachedSignature(detachedSignature) ?: return false
            if (signature.signatureType != PGPSignature.BINARY_DOCUMENT) return false
            val signingKey = ring.getPublicKey(signature.keyID) ?: return false
            signature.init(BcPGPContentVerifierBuilderProvider(), signingKey)
            signature.update(canonicalMessage(bundle, oldHash, newHash))
            signature.verify()
        } catch (_: IOException) {
            false
        } catch (_: PGPException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    internal fun canonicalMessage(bundle: ByteArray, oldHash: String, newHash: String): ByteArray {
        require(lowerHex.matches(oldHash) && lowerHex.matches(newHash) && oldHash != newHash)
        val prefix =
            "RKA_AGENT_ROOT_ROTATION_V1\n" +
                "old_sha256=$oldHash\n" +
                "new_sha256=$newHash\n" +
                "bundle_size=${bundle.size}\n\n"
        return prefix.toByteArray(StandardCharsets.US_ASCII) + bundle
    }

    internal fun inspectAnchor(anchor: ByteArray): AgentPgpAnchorInspection {
        var primary = 0
        var subkeys = 0
        var userIds = 0
        var userAttributes = 0
        var secretKeys = 0
        var signatures = 0
        var other = 0
        BCPGInputStream(ByteArrayInputStream(anchor)).use { packets ->
            while (packets.nextPacketTag() >= 0) {
                when (packets.nextPacketTag()) {
                    PacketTags.PUBLIC_KEY -> primary += 1
                    PacketTags.PUBLIC_SUBKEY -> subkeys += 1
                    PacketTags.USER_ID -> userIds += 1
                    PacketTags.USER_ATTRIBUTE -> userAttributes += 1
                    PacketTags.SECRET_KEY,
                    PacketTags.SECRET_SUBKEY -> secretKeys += 1
                    PacketTags.SIGNATURE -> signatures += 1
                    else -> other += 1
                }
                packets.readPacket()
            }
        }
        return AgentPgpAnchorInspection(
            primary,
            subkeys,
            userIds,
            userAttributes,
            secretKeys,
            signatures,
            other,
        )
    }

    private fun authorizationMatches(bundle: ByteArray, oldHash: String, newHash: String): Boolean {
        val text =
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bundle))
                .toString()
        val authorizations = text.lineSequence().filter { it.startsWith("authorization=") }.toList()
        if (authorizations.size != 1) return false
        val statement =
            "RKA_AGENT_ROOT_ROTATION_AUTH_V1\n" + "old_sha256=$oldHash\n" + "new_sha256=$newHash\n"
        val expected =
            MessageDigest.getInstance("SHA-256")
                .digest(statement.toByteArray(StandardCharsets.US_ASCII))
                .joinToString("") { "%02x".format(it) }
        return authorizations.single() == "authorization=$expected"
    }

    private fun detachedSignature(encoded: ByteArray): PGPSignature? {
        val objects = PGPObjectFactory(encoded, BcKeyFingerprintCalculator())
        val signatures = objects.nextObject() as? PGPSignatureList ?: return null
        if (signatures.size() != 1 || objects.nextObject() != null) return null
        return signatures[0]
    }

    private fun hexBytes(value: String): ByteArray =
        ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }

    private fun readBounded(path: Path, maximum: Int): ByteArray {
        val attributes =
            Files.readAttributes(
                path,
                java.nio.file.attribute.BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
        require(attributes.isRegularFile && attributes.size() in 1..maximum.toLong())
        return Files.readAllBytes(path).also { require(it.size <= maximum) }
    }
}
