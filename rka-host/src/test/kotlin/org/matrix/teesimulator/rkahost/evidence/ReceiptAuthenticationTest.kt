package org.matrix.teesimulator.rkahost.evidence

import java.security.KeyPairGenerator
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ReceiptAuthenticationTest {
    private val rootPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val rootSigner = Ed25519ReceiptSigner("root-key", rootPair.private)
    private val trustedKeys = mapOf(rootSigner.keyId to rootPair.public)

    @Test
    fun ed25519_round_trip_is_deterministic_for_canonical_receipt_bytes() {
        val encoded = issue("nonce-roundtrip")
        val unsigned = encoded.substringBefore("signer=").toByteArray()
        val first = rootSigner.signReceipt(unsigned)
        val second = rootSigner.signReceipt(unsigned)

        assertArrayEquals(first, second)
        assertEquals(64, first.size)
        ReceiptVerifier(trustedKeys).verify(encoded, binding("nonce-roundtrip"))
    }

    @Test
    fun rejects_attacker_key_reusing_the_trusted_key_id() {
        val encoded = issue("nonce-substituted")
        val attacker = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val forged = resign(encoded, Ed25519ReceiptSigner("root-key", attacker.private))

        assertEquals(
            "RECEIPT_SIGNATURE_INVALID",
            assertThrows(ReceiptException::class.java) {
                    ReceiptVerifier(trustedKeys).verify(forged, binding("nonce-substituted"))
                }
                .message,
        )
    }

    @Test
    fun rejects_unknown_and_wrong_pinned_public_keys() {
        val encoded = issue("nonce-key")
        val other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

        assertEquals(
            "RECEIPT_SIGNER_UNTRUSTED",
            assertThrows(ReceiptException::class.java) {
                    ReceiptVerifier(mapOf("other-key" to rootPair.public))
                        .verify(encoded, binding("nonce-key"))
                }
                .message,
        )
        assertEquals(
            "RECEIPT_SIGNATURE_INVALID",
            assertThrows(ReceiptException::class.java) {
                    ReceiptVerifier(mapOf("root-key" to other.public))
                        .verify(encoded, binding("nonce-key"))
                }
                .message,
        )
    }

    @Test
    fun rejects_signature_bitflip_truncation_and_extension() {
        val encoded = issue("nonce-signature")
        val signature = encoded.substringAfter("signature=").substringBefore('\n')
        val bitflip = signature.replaceRange(0, 1, if (signature[0] == 'A') "B" else "A")
        val truncated = signature.dropLast(1)
        val extended = "$signature" + "A"

        listOf(bitflip, truncated, extended).forEach { replacement ->
            val tampered = encoded.replace("signature=$signature", "signature=$replacement")
            assertEquals(
                "RECEIPT_SIGNATURE_INVALID",
                assertThrows(ReceiptException::class.java) {
                        ReceiptVerifier(trustedKeys).verify(tampered, binding("nonce-signature"))
                    }
                    .message,
            )
        }
    }

    private fun issue(nonce: String): String {
        val service = ServiceIdentity("keystore2", "init", 42, 100, "/system/bin/keystore2", 0)
        val properties = mapOf("ro.build.fingerprint" to "build-A")
        val live =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A", MonotonicClock { 2_000 })
                .observe(SentinelSample("boot-A", 0, properties, emptySet(), 0), service)
                .observe(SentinelSample("boot-A", 2_000, properties, emptySet(), 2_000), service)
                .assertLive(2_000)
        return EvidenceIssuer.sign(
            live,
            binding(nonce),
            ReceiptMaterial(
                EvidenceHash.sha256("trace"),
                EvidenceHash.sha256("artifact"),
                monotonicMillis = 2_000,
            ),
            rootSigner,
        )
    }

    private fun resign(encoded: String, signer: Ed25519ReceiptSigner): String {
        val unsigned = encoded.substringBefore("signer=")
        val signature =
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(signer.signReceipt(unsigned.toByteArray()))
        return unsigned + "signer=${signer.keyId}\n" + "signature=$signature\n"
    }

    private fun binding(nonce: String) =
        ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", nonce)
}
