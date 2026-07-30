package org.matrix.teesimulator.rkahost.evidence

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CommandReceiptTest {
    @Test
    fun rejects_forbidden_argv_before_runner_execution() {
        // Given: a counting runner and dangerous literal/shell-smuggled argv variants.
        val runner = RecordingRunner()
        val commands =
            listOf(
                listOf("adb", "-s", "serial-A", "reboot"),
                listOf("adb", "-s", "serial-A", "shell", "reboot"),
                listOf("adb", "-s", "serial-A", "shell", "kill", "-9", "1"),
                listOf("adb", "-s", "serial-A", "shell", "getprop;reboot"),
                listOf("adb", "-s", "serial-A", "shell", "setprop", "ctl.restart", "keystore2"),
            )

        // When/Then: all are rejected before process execution.
        commands.forEach { argv ->
            assertThrows(CommandRejected::class.java) { AdbCommandPolicy(runner).execute(argv) }
        }
        assertEquals(0, runner.calls)
    }

    @Test
    fun permits_only_literal_read_only_argv_and_models_future_operations() {
        // Given: a fake ADB runner.
        val runner = RecordingRunner()

        // When: a literal allowlisted property read is traced.
        val trace =
            AdbCommandPolicy(runner)
                .execute(
                    listOf("adb", "-s", "serial-A", "shell", "getprop", "ro.build.fingerprint")
                )

        // Then: it executes once without leaking the serial and future service operations stay
        // plans only.
        assertEquals(1, runner.calls)
        assertFalse(trace.canonical().contains("serial-A"))
        assertEquals(false, FutureServiceOperation.KEYSTORE2_STATUS.executed)
        assertEquals(false, FutureServiceOperation.RKPD_STATUS.executed)
    }

    @Test
    fun classifies_reboot_before_any_runner_or_shape_fallback() {
        // Given: a literal reboot argv whose only valid outcome is a hard no-reboot classification.
        val runner = RecordingRunner()

        // When: the policy receives it.
        val failure =
            assertThrows(CommandRejected::class.java) {
                AdbCommandPolicy(runner).execute(listOf("adb", "-s", "serial-A", "shell", "reboot"))
            }

        // Then: it is classified as forbidden before it could reach a runner.
        assertEquals("ADB_FORBIDDEN_OPERATION", failure.message)
        assertEquals(0, runner.calls)
    }

    @Test
    fun receipts_reject_nonce_binding_signature_and_chain_attacks() {
        // Given: a deterministic signer and canonical signed receipt.
        val signer = DigestSigner("test-key")
        val receipt = ReceiptFactory.valid("nonce-A")
        val encoded = ReceiptCodec.encode(receipt, signer)

        // When/Then: verification rejects wrong binding, replay, tamper, noncanonical, reorder, and
        // truncation.
        val verifier = ReceiptVerifier(signer)
        verifier.verify(
            encoded,
            ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
        )
        assertThrows(ReceiptException::class.java) {
            verifier.verify(
                encoded,
                ReceiptBinding("commit-B", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
            )
        }
        assertThrows(ReceiptException::class.java) {
            verifier.verify(
                encoded,
                ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
            )
        }
        assertThrows(ReceiptException::class.java) {
            verifier.verify(
                encoded.replace("commit-A", "commit-X"),
                ReceiptBinding("commit-X", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            ReceiptCodec.decode(encoded.replace("version=1\n", "role=DONOR\nversion=1\n"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ReceiptCodec.decode(encoded.substringBeforeLast("signature=") + "signature=")
        }
        val tamperedSignature = encoded.replace(Regex("(?m)^signature=."), "signature=A")
        val signatureFailure =
            assertThrows(ReceiptException::class.java) {
                ReceiptVerifier(signer)
                    .verify(
                        tamperedSignature,
                        ReceiptBinding(
                            "commit-A",
                            "profile-A",
                            EndpointRole.DONOR,
                            "session-A",
                            "nonce-A",
                        ),
                    )
            }
        assertEquals("RECEIPT_SIGNATURE_INVALID", signatureFailure.message)
    }

    @Test
    fun atomic_store_leaves_old_or_new_never_partial_and_rejects_paths_modes_and_symlinks() {
        // Given: a secure temporary root and a receipt store.
        val root = Files.createTempDirectory("rka-receipt-")
        try {
            val store = AtomicReceiptStore(root, DigestSigner("test-key"))
            val first = ReceiptFactory.valid("nonce-1")

            // When: an interrupted replacement occurs after the durable temporary write.
            store.write("receipt", first)
            assertThrows(ReceiptException::class.java) {
                store.write(
                    "receipt",
                    ReceiptFactory.valid("nonce-2"),
                    interruptBeforeRename = true,
                )
            }

            // Then: only the previous complete receipt remains; unsafe paths are refused.
            assertTrue(Files.readString(root.resolve("receipt.receipt")).contains("nonce-1"))
            assertThrows(ReceiptException::class.java) { store.write("../escape", first) }
            Files.createSymbolicLink(root.resolve("link.receipt"), root.resolve("receipt.receipt"))
            assertThrows(ReceiptException::class.java) { store.read("link") }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private class RecordingRunner : LiteralCommandRunner {
        var calls = 0

        override fun run(argv: List<String>): CommandResult {
            calls += 1
            return CommandResult(0, "ok")
        }
    }
}
