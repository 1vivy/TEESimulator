package org.matrix.teesimulator.rkafixture

import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FixtureRequestStagingTest {
    @Test
    fun atomicallyConsumesOneCompletedUploadAndRejectsReplay() {
        // Given: one canonical staged request. When: it is executed twice. Then: the first consume
        // returns the exact input and the second is a typed duplicate execution.
        withStaging { staging, nonce, request, _ ->
            staging.beginUpload(nonce).writeFrom(request.byteInputStream())

            val input = staging.consume(nonce)

            assertContentEquals(nonceBytes(), input.nonce)
            assertFailsWith<FixtureProviderError.DuplicateExecute> { staging.consume(nonce) }
        }
    }

    @Test
    fun recoversACompletedUploadAfterTheProviderProcessRestarts() {
        // Given: a completed request persisted before the provider process exits. When: a new
        // staging instance starts from the same directory. Then: it consumes the saved request.
        val directory = Files.createTempDirectory("fixture-request-recovery").toFile()
        try {
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            val request =
                "{\"version\":1,\"command\":\"status\",\"nonce\":\"$nonce\",\"metadata\":{\"roles\":[\"TARGET\"]}}"
            FixtureRequestStaging(directory, { 0L })
                .beginUpload(nonce)
                .writeFrom(request.byteInputStream())

            val recovered = FixtureRequestStaging(directory, { 0L })

            assertContentEquals(nonceBytes(), recovered.consume(nonce).nonce)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun completesAProxyUploadOnlyAfterRelease() {
        // Given: a sequential proxy upload. When: its release callback finalizes the request.
        // Then: execute consumes exactly the canonical request.
        withStaging { staging, nonce, request, _ ->
            val upload = staging.beginProxyUpload(nonce)
            upload.writeAt(0, request.encodeToByteArray(), request.length)
            upload.release()

            assertContentEquals(nonceBytes(), staging.consume(nonce).nonce)
        }
    }

    @Test
    fun rejectsAProxyUploadLargerThanTheRequestLimit() {
        // Given: a bounded proxy upload. When: a write crosses its byte limit.
        // Then: it rejects the write before an oversized request can reach durable storage.
        withStaging { staging, nonce, _, _ ->
            val upload = staging.beginProxyUpload(nonce)

            assertFailsWith<FixtureProviderError.OversizedRequest> {
                upload.writeAt(0, ByteArray(1_048_577), 1_048_577)
            }
        }
    }

    @Test
    fun restoresAReleasedProxyUploadAcrossRestart() {
        // Given: a released proxy upload. When: a new staging instance starts.
        // Then: the ready request survives process replacement.
        val directory = Files.createTempDirectory("fixture-proxy-restart").toFile()
        try {
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            val request =
                "{\"version\":1,\"command\":\"status\",\"nonce\":\"$nonce\",\"metadata\":{\"roles\":[\"TARGET\"]}}"
            FixtureRequestStaging(directory, { 0L }).beginProxyUpload(nonce).also { upload ->
                upload.writeAt(0, request.encodeToByteArray(), request.length)
                upload.release()
            }

            assertContentEquals(
                nonceBytes(),
                FixtureRequestStaging(directory, { 0L }).consume(nonce).nonce,
            )
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun preservesReplayTombstonesAcrossRestart() {
        // Given: a consumed released upload. When: a new provider process executes its nonce.
        // Then: durable bounded replay state returns the established duplicate failure.
        val directory = Files.createTempDirectory("fixture-proxy-replay").toFile()
        try {
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            val request =
                "{\"version\":1,\"command\":\"status\",\"nonce\":\"$nonce\",\"metadata\":{\"roles\":[\"TARGET\"]}}"
            FixtureRequestStaging(directory, { 0L })
                .beginProxyUpload(nonce)
                .also { upload ->
                    upload.writeAt(0, request.encodeToByteArray(), request.length)
                    upload.release()
                }
                .let { FixtureRequestStaging(directory, { 0L }).consume(nonce) }

            assertFailsWith<FixtureProviderError.DuplicateExecute> {
                FixtureRequestStaging(directory, { 0L }).consume(nonce)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun rejectsARecreatedReadyFileWhenItsTombstoneSurvivesRestart() {
        // Given: a consumed request and a stale ready artifact recreated after its tombstone.
        // When: a new staging instance starts. Then: the tombstone blocks a second execution.
        val directory = Files.createTempDirectory("fixture-stale-ready").toFile()
        try {
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            val request =
                "{\"version\":1,\"command\":\"status\",\"nonce\":\"$nonce\",\"metadata\":{\"roles\":[\"TARGET\"]}}"
            FixtureRequestStaging(directory, { 0L })
                .beginProxyUpload(nonce)
                .also { upload ->
                    upload.writeAt(0, request.encodeToByteArray(), request.length)
                    upload.release()
                }
                .let { FixtureRequestStaging(directory, { 0L }).consume(nonce) }
            java.io.File(directory, nonce + FIXTURE_REQUEST_READY_SUFFIX).writeText(request)

            assertFailsWith<FixtureProviderError.DuplicateExecute> {
                FixtureRequestStaging(directory, { 0L }).consume(nonce)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun closesTheProxySinkWhenSyncFailsDuringRelease() {
        // Given: a proxy sink whose fsync fails. When: release finalizes the upload.
        // Then: the sink is closed and the request fails with a typed interruption.
        val directory = Files.createTempDirectory("fixture-proxy-sync-failure").toFile()
        try {
            val sink = FailingSyncSink()
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            val staging = FixtureRequestStaging(directory, { 0L }, proxySinkFactory = { sink })

            assertFailsWith<FixtureProviderError.UploadInterrupted> {
                staging.beginProxyUpload(nonce).release()
            }
            assertTrue(sink.closed)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun discardsAnUnreleasedProxyUploadAcrossRestart() {
        // Given: a proxy upload whose writer never releases. When: the provider restarts.
        // Then: the interrupted upload cannot be executed.
        val directory = Files.createTempDirectory("fixture-proxy-abandoned").toFile()
        try {
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            FixtureRequestStaging(directory, { 0L }).beginProxyUpload(nonce)

            assertFailsWith<FixtureProviderError.MissingRequest> {
                FixtureRequestStaging(directory, { 0L }).consume(nonce)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun malformedInterruptedAndOversizedUploadsLeaveNoStagedState() {
        // Given: malformed, truncated, and oversized request streams. When: each upload ends.
        // Then: each failure deletes the temporary state and permits no later execution.
        withStaging { staging, nonce, request, _ ->
            assertFailsWith<FixtureProviderError.MalformedRequest> {
                staging.beginUpload(nonce).writeFrom(request.dropLast(1).byteInputStream())
            }
            assertFalse(staging.hasStagedRequest(nonce))
            assertFailsWith<FixtureProviderError.MissingRequest> { staging.consume(nonce) }

            assertFailsWith<FixtureProviderError.MalformedRequest> {
                staging.beginUpload(nonce).writeFrom((request + "\n").byteInputStream())
            }
            assertFalse(staging.hasStagedRequest(nonce))

            assertFailsWith<FixtureProviderError.UploadInterrupted> {
                staging.beginUpload(nonce).writeFrom(BrokenInputStream)
            }
            assertFalse(staging.hasStagedRequest(nonce))

            assertFailsWith<FixtureProviderError.OversizedRequest> {
                staging.beginUpload(nonce).writeFrom(ByteArray(1_048_577).inputStream())
            }
            assertFalse(staging.hasStagedRequest(nonce))
        }
    }

    @Test
    fun duplicateUploadsAndAbandonedUploadsAreCleanedDeterministically() {
        // Given: an active upload and a controllable clock. When: a duplicate starts or the slot
        // expires. Then: duplicate upload is typed and TTL cleanup removes all task state.
        withStaging { staging, nonce, _, clock ->
            staging.beginUpload(nonce)

            assertFailsWith<FixtureProviderError.DuplicateUpload> { staging.beginUpload(nonce) }
            clock.nowMillis += FixtureRequestStaging.UPLOAD_TTL_MILLIS + 1
            staging.cleanupExpired()

            assertFalse(staging.hasStagedRequest(nonce))
        }
    }

    @Test
    fun executionTimeoutClosesAnUnfinishedUploadAndLeavesNoState() {
        // Given: an upload whose execute wait budget is exhausted. When: execution consumes it.
        // Then: the pending upload is canceled, typed as a timeout, and leaves no staged request.
        val directory = Files.createTempDirectory("fixture-request-timeout").toFile()
        try {
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            val staging =
                FixtureRequestStaging(
                    directory,
                    { 0L },
                    FixtureStagingLimits(executeWaitMillis = 0L),
                )
            staging.beginUpload(nonce)

            assertFailsWith<FixtureProviderError.UploadTimeout> { staging.consume(nonce) }
            assertFalse(staging.hasStagedRequest(nonce))
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun withStaging(block: (FixtureRequestStaging, String, String, TestClock) -> Unit) {
        val directory = Files.createTempDirectory("fixture-request-staging").toFile()
        try {
            val clock = TestClock()
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes())
            block(
                FixtureRequestStaging(directory, clock::read),
                nonce,
                "{\"version\":1,\"command\":\"status\",\"nonce\":\"$nonce\",\"metadata\":{\"roles\":[\"TARGET\"]}}",
                clock,
            )
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun nonceBytes() = ByteArray(FixtureNonce.BYTES) { (it + 1).toByte() }

    private class TestClock {
        var nowMillis = 0L

        fun read(): Long = nowMillis
    }

    private data object BrokenInputStream : InputStream() {
        override fun read(): Int = throw IOException("interrupted upload")
    }

    private class FailingSyncSink : FixtureRequestSink {
        var closed = false

        override fun write(data: ByteArray, size: Int) = Unit

        override fun sync(): Nothing = throw IOException("sync failure")

        override fun close() {
            closed = true
        }
    }
}
