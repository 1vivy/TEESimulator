package org.matrix.teesimulator.rkahost.evidence

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64

data class ReceiptBinding(
    val commit: String,
    val profile: String,
    val role: EndpointRole,
    val session: String,
    val nonce: String,
)

data class ReceiptMaterial(
    val commandTraceHash: String,
    val artifactHash: String,
    val previousHash: String = "0",
    val monotonicMillis: Long,
)

object EvidenceIssuer {
    fun sign(
        live: LiveSentinelEvidence,
        binding: ReceiptBinding,
        material: ReceiptMaterial,
        signer: ReceiptSigner,
    ): String {
        val values = live.values
        require(binding.profile == values.profileId && binding.role == values.role) {
            "RECEIPT_BINDING_MISMATCH"
        }
        return ReceiptCodec.encode(
            EvidenceReceipt(
                binding.commit,
                binding.profile,
                binding.role,
                binding.session,
                binding.nonce,
                values.serialHash,
                values.bootId,
                values.headUptimeMillis,
                values.tailUptimeMillis,
                values.sampleCount,
                values.headObservedAtMillis,
                values.tailObservedAtMillis,
                values.assertedAtMillis,
                values.sampleChainHash,
                EvidenceHash.sha256(values.service.canonical()),
                EvidenceHash.sha256(values.propertyNames.joinToString(",")),
                values.propertyHash,
                material.commandTraceHash,
                material.artifactHash,
                material.previousHash,
                material.monotonicMillis,
            ),
            signer,
        )
    }
}

private data class EvidenceReceipt(
    val commit: String,
    val profile: String,
    val role: EndpointRole,
    val session: String,
    val nonce: String,
    val serialHash: String,
    val bootId: String,
    val sampleHead: Long,
    val sampleTail: Long,
    val sampleCount: Int,
    val headObservedAt: Long,
    val tailObservedAt: Long,
    val assertedAt: Long,
    val sampleChainHash: String,
    val serviceHash: String,
    val propertyDefinitionHash: String,
    val propertyHash: String,
    val commandTraceHash: String,
    val artifactHash: String,
    val previousHash: String,
    val monotonicMillis: Long,
) {
    fun fields(): List<Pair<String, String>> =
        listOf(
            "version" to "1",
            "commit" to commit,
            "profile" to profile,
            "role" to role.name,
            "session" to session,
            "nonce" to nonce,
            "serial_hash" to serialHash,
            "boot_id" to bootId,
            "sample_head" to sampleHead.toString(),
            "sample_tail" to sampleTail.toString(),
            "sample_count" to sampleCount.toString(),
            "head_observed_at" to headObservedAt.toString(),
            "tail_observed_at" to tailObservedAt.toString(),
            "asserted_at" to assertedAt.toString(),
            "sample_chain_hash" to sampleChainHash,
            "service_hash" to serviceHash,
            "property_definition_hash" to propertyDefinitionHash,
            "property_hash" to propertyHash,
            "command_trace_hash" to commandTraceHash,
            "artifact_hash" to artifactHash,
            "previous_hash" to previousHash,
            "monotonic_millis" to monotonicMillis.toString(),
        )
}

interface ReceiptSigner {
    val keyId: String

    fun sign(canonical: ByteArray): ByteArray

    fun verify(canonical: ByteArray, signature: ByteArray): Boolean
}

class DigestSigner(override val keyId: String) : ReceiptSigner {
    override fun sign(canonical: ByteArray): ByteArray =
        EvidenceHash.sha256(keyId.toByteArray() + canonical)
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    override fun verify(canonical: ByteArray, signature: ByteArray): Boolean =
        sign(canonical).contentEquals(signature)
}

class ReceiptException(message: String) : IllegalStateException(message)

private object ReceiptCodec {
    private val text = Regex("[A-Za-z0-9._/-]{1,160}")
    private val hash = Regex("[0-9a-f]{64}")

    fun encode(receipt: EvidenceReceipt, signer: ReceiptSigner): String {
        validate(receipt)
        val unsigned = receipt.fields().joinToString("\n") { "${it.first}=${it.second}" } + "\n"
        val signature =
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(signer.sign(unsigned.toByteArray()))
        return unsigned + "signer=${signer.keyId}\n" + "signature=$signature\n"
    }

    fun decode(encoded: String): DecodedReceipt {
        require(!encoded.contains('\r')) { "RECEIPT_NONCANONICAL" }
        val lines = encoded.split('\n').dropLast(1)
        require(encoded.endsWith("\n") && lines.size == 24) { "RECEIPT_TRUNCATED" }
        val pairs =
            lines.map { line ->
                line.split('=', limit = 2).let {
                    require(it.size == 2) { "RECEIPT_NONCANONICAL" }
                    it[0] to it[1]
                }
            }
        val expected =
            EvidenceReceipt(
                    "c",
                    "p",
                    EndpointRole.DONOR,
                    "s",
                    "n",
                    "h",
                    "b",
                    0,
                    1,
                    2,
                    0,
                    1,
                    1,
                    "h",
                    "h",
                    "h",
                    "h",
                    "h",
                    "h",
                    "0",
                    0,
                )
                .fields()
                .map { it.first } + listOf("signer", "signature")
        require(pairs.map { it.first } == expected) { "RECEIPT_NONCANONICAL" }
        val fields = pairs.toMap()
        require(fields.getValue("version") == "1") { "RECEIPT_VERSION_INVALID" }
        val receipt =
            EvidenceReceipt(
                fields.getValue("commit"),
                fields.getValue("profile"),
                EndpointRole.valueOf(fields.getValue("role")),
                fields.getValue("session"),
                fields.getValue("nonce"),
                fields.getValue("serial_hash"),
                fields.getValue("boot_id"),
                fields.getValue("sample_head").toLong(),
                fields.getValue("sample_tail").toLong(),
                fields.getValue("sample_count").toInt(),
                fields.getValue("head_observed_at").toLong(),
                fields.getValue("tail_observed_at").toLong(),
                fields.getValue("asserted_at").toLong(),
                fields.getValue("sample_chain_hash"),
                fields.getValue("service_hash"),
                fields.getValue("property_definition_hash"),
                fields.getValue("property_hash"),
                fields.getValue("command_trace_hash"),
                fields.getValue("artifact_hash"),
                fields.getValue("previous_hash"),
                fields.getValue("monotonic_millis").toLong(),
            )
        validate(receipt)
        val signature =
            try {
                Base64.getUrlDecoder().decode(fields.getValue("signature"))
            } catch (_: IllegalArgumentException) {
                throw ReceiptException("RECEIPT_SIGNATURE_INVALID")
            }
        require(
            Base64.getUrlEncoder().withoutPadding().encodeToString(signature) ==
                fields.getValue("signature")
        ) {
            "RECEIPT_NONCANONICAL"
        }
        val unsigned = receipt.fields().joinToString("\n") { "${it.first}=${it.second}" } + "\n"
        return DecodedReceipt(receipt, fields.getValue("signer"), signature, unsigned.toByteArray())
    }

    private fun validate(receipt: EvidenceReceipt) {
        require(
            listOf(
                    receipt.commit,
                    receipt.profile,
                    receipt.session,
                    receipt.nonce,
                    receipt.serialHash,
                    receipt.bootId,
                    receipt.serviceHash,
                    receipt.propertyDefinitionHash,
                    receipt.propertyHash,
                    receipt.commandTraceHash,
                    receipt.artifactHash,
                    receipt.previousHash,
                    receipt.sampleChainHash,
                )
                .all(text::matches)
        ) {
            "RECEIPT_FIELD_INVALID"
        }
        require(
            listOf(
                    receipt.serialHash,
                    receipt.sampleChainHash,
                    receipt.serviceHash,
                    receipt.propertyDefinitionHash,
                    receipt.propertyHash,
                    receipt.commandTraceHash,
                    receipt.artifactHash,
                )
                .all(hash::matches) &&
                (receipt.previousHash == "0" || hash.matches(receipt.previousHash))
        ) {
            "RECEIPT_HASH_INVALID"
        }
        require(
            receipt.sampleHead >= 0 &&
                receipt.sampleTail >= receipt.sampleHead &&
                receipt.sampleCount >= 2 &&
                receipt.sampleCount <= NoRebootSentinel.MAXIMUM_SAMPLES &&
                receipt.headObservedAt >= 0 &&
                receipt.tailObservedAt > receipt.headObservedAt &&
                receipt.tailObservedAt - receipt.headObservedAt <= 2_000 &&
                receipt.assertedAt >= receipt.tailObservedAt &&
                receipt.assertedAt - receipt.tailObservedAt <= 2_000 &&
                receipt.monotonicMillis >= 0
        ) {
            "RECEIPT_TIME_INVALID"
        }
    }
}

private data class DecodedReceipt(
    val receipt: EvidenceReceipt,
    val signerId: String,
    val signature: ByteArray,
    val unsigned: ByteArray,
)

class ReceiptVerifier(private val signer: ReceiptSigner) {
    private val consumedNonces = mutableSetOf<String>()
    private var previousHash: String? = null

    fun verify(encoded: String, binding: ReceiptBinding): VerifiedEvidence {
        val decoded =
            try {
                ReceiptCodec.decode(encoded)
            } catch (failure: IllegalArgumentException) {
                throw ReceiptException(failure.message ?: "RECEIPT_INVALID")
            }
        val receipt = decoded.receipt
        if (decoded.signerId != signer.keyId || !signer.verify(decoded.unsigned, decoded.signature))
            throw ReceiptException("RECEIPT_SIGNATURE_INVALID")
        if (
            receipt.commit != binding.commit ||
                receipt.profile != binding.profile ||
                receipt.role != binding.role ||
                receipt.session != binding.session ||
                receipt.nonce != binding.nonce
        )
            throw ReceiptException("RECEIPT_BINDING_MISMATCH")
        if (!consumedNonces.add(receipt.nonce)) throw ReceiptException("RECEIPT_REPLAY")
        val expectedPrevious = previousHash ?: "0"
        if (receipt.previousHash != expectedPrevious)
            throw ReceiptException("RECEIPT_CHAIN_INVALID")
        previousHash = EvidenceHash.sha256(encoded)
        return VerifiedEvidence(receipt.sampleCount, receipt.sampleChainHash)
    }
}

class VerifiedEvidence internal constructor(
    val sampleCount: Int,
    val sampleChainHash: String,
)

class AtomicReceiptStore(private val root: Path) {
    init {
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(root)) {
            "RECEIPT_ROOT_INVALID"
        }
    }

    fun write(name: String, encoded: String, interruptBeforeRename: Boolean = false) {
        val target = target(name)
        if (
            Files.exists(target, LinkOption.NOFOLLOW_LINKS) &&
                (Files.isSymbolicLink(target) ||
                    !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS))
        )
            throw ReceiptException("RECEIPT_PATH_UNSAFE")
        val temporary = Files.createTempFile(root, ".receipt-", ".tmp")
        try {
            Files.setPosixFilePermissions(
                temporary,
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
            )
            FileChannel.open(temporary, StandardOpenOption.WRITE).use { channel ->
                channel.write(
                    java.nio.ByteBuffer.wrap(encoded.toByteArray())
                )
                channel.force(true)
            }
            if (interruptBeforeRename) throw ReceiptException("RECEIPT_INTERRUPTED")
            Files.move(
                temporary,
                target,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            FileChannel.open(root, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    fun read(name: String): String {
        val target = target(name)
        if (Files.isSymbolicLink(target) || !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS))
            throw ReceiptException("RECEIPT_PATH_UNSAFE")
        val mode = Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS)
        if (
            mode.any {
                it !in setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            }
        )
            throw ReceiptException("RECEIPT_MODE_UNSAFE")
        return Files.readString(target)
    }

    private fun target(name: String): Path {
        if (!name.matches(Regex("[A-Za-z0-9._-]{1,64}")))
            throw ReceiptException("RECEIPT_NAME_INVALID")
        return root.resolve("$name.receipt")
    }
}
