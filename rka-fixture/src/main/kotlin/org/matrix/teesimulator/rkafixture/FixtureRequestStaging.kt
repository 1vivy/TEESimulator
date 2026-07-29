package org.matrix.teesimulator.rkafixture

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal const val FIXTURE_REQUEST_UPLOAD_SUFFIX = ".upload"
internal const val FIXTURE_REQUEST_READY_SUFFIX = ".ready"

interface FixtureRequestSink {
    fun write(data: ByteArray, size: Int)

    fun sync()

    fun close()
}

internal class FileRequestSink(private val output: FileOutputStream) : FixtureRequestSink {
    override fun write(data: ByteArray, size: Int) {
        output.write(data, 0, size)
    }

    override fun sync() {
        FixtureRequestFiles.sync(output)
    }

    override fun close() {
        output.close()
    }
}

class FixtureRequestStaging(
    private val directory: File,
    private val nowMillis: () -> Long,
    private val limits: FixtureStagingLimits = FixtureStagingLimits(),
    private val proxySinkFactory: (File) -> FixtureRequestSink = { file ->
        FileRequestSink(FileOutputStream(file))
    },
) {
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val states = mutableMapOf<String, RequestState>()
    private val consumed: FixtureReplayTombstones
    private val expired = RecentTokens()

    init {
        require(limits.uploadTtlMillis > 0)
        require(limits.executeWaitMillis >= 0)
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("cannot create request staging")
        }
        if (!directory.isDirectory) throw IOException("request staging is not a directory")
        consumed = FixtureReplayTombstones(directory)
        FixtureStagedRequestRecovery.recover(directory, nowMillis(), limits.uploadTtlMillis)
            .forEach { recovered ->
                if (recovered.nonce in consumed) {
                    recovered.file.delete()
                } else {
                    states[recovered.nonce] =
                        RequestState.Ready(
                            recovered.file,
                            recovered.input,
                            recovered.expiresAtMillis,
                        )
                }
            }
    }

    fun beginUpload(nonce: String): FixtureRequestUpload =
        FixtureRequestUpload(this, nonce, begin(nonce))

    fun beginProxyUpload(nonce: String): FixtureProxyUpload =
        FixtureProxyUpload(this, nonce, begin(nonce))

    fun consume(nonce: String): FixtureCommandInput {
        validateNonce(nonce)
        val ready =
            lock.withLock {
                if (nonce in consumed) {
                    states.remove(nonce)?.file?.delete()
                    throw FixtureProviderError.DuplicateExecute
                }
                val state = awaitReadyLocked(nonce)
                states.remove(nonce)
                if (state !is RequestState.Ready) throw missingOrDuplicate(nonce)
                consumed.add(nonce)
                state
            }
        ready.file.delete()
        return ready.input
    }

    fun cleanup(nonce: String): Boolean {
        validateNonce(nonce)
        val state = lock.withLock { states.remove(nonce) }
        state?.file?.delete()
        return state != null
    }

    fun cleanupExpired() {
        lock.withLock { cleanupExpiredLocked() }
    }

    fun hasStagedRequest(nonce: String): Boolean = lock.withLock { nonce in states }

    internal fun complete(nonce: String, temporary: File) {
        val input =
            try {
                FixtureRequestFiles.decode(temporary)
            } catch (failure: FixtureProviderError) {
                abort(nonce, temporary)
                throw failure
            }
        lock.withLock {
            val state = states[nonce]
            if (state !is RequestState.Uploading || state.file != temporary) {
                throw FixtureProviderError.UploadInterrupted
            }
            val ready = File(directory, nonce + FIXTURE_REQUEST_READY_SUFFIX)
            if (!temporary.renameTo(ready)) throw FixtureProviderError.UploadInterrupted
            states[nonce] = RequestState.Ready(ready, input, deadline())
            changed.signalAll()
        }
    }

    internal fun abort(nonce: String, temporary: File) {
        temporary.delete()
        lock.withLock {
            if (states[nonce] is RequestState.Uploading) states.remove(nonce)
            changed.signalAll()
        }
    }

    private fun begin(nonce: String): File {
        validateNonce(nonce)
        val temporary = File(directory, nonce + FIXTURE_REQUEST_UPLOAD_SUFFIX)
        lock.withLock {
            cleanupExpiredLocked()
            if (nonce in states || nonce in consumed) throw FixtureProviderError.DuplicateUpload
            states[nonce] = RequestState.Uploading(temporary, deadline())
        }
        return temporary
    }

    private fun awaitReadyLocked(nonce: String): RequestState {
        var remainingNanos = TimeUnit.MILLISECONDS.toNanos(limits.executeWaitMillis)
        while (states[nonce] is RequestState.Uploading && remainingNanos > 0) {
            remainingNanos =
                try {
                    changed.awaitNanos(remainingNanos)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw FixtureProviderError.UploadInterrupted
                }
        }
        cleanupExpiredLocked()
        if (states[nonce] is RequestState.Uploading) {
            val state = states.remove(nonce) as RequestState.Uploading
            state.file.delete()
            expired.add(nonce)
            throw FixtureProviderError.UploadTimeout
        }
        return states[nonce] ?: throw missingOrDuplicate(nonce)
    }

    private fun cleanupExpiredLocked() {
        val now = nowMillis()
        states
            .filterValues { state -> state.expiresAtMillis <= now }
            .keys
            .toList()
            .forEach { nonce ->
                states.remove(nonce)?.file?.delete()
                expired.add(nonce)
            }
    }

    private fun missingOrDuplicate(nonce: String): Nothing {
        if (nonce in consumed) throw FixtureProviderError.DuplicateExecute
        if (nonce in expired) throw FixtureProviderError.UploadTimeout
        throw FixtureProviderError.MissingRequest
    }

    private fun deadline(): Long = nowMillis() + limits.uploadTtlMillis

    private fun validateNonce(nonce: String) {
        if (!NONCE.matches(nonce)) throw FixtureProviderError.InvalidNonce
        val bytes =
            try {
                Base64.getUrlDecoder().decode(nonce)
            } catch (_: IllegalArgumentException) {
                throw FixtureProviderError.InvalidNonce
            }
        if (bytes.size != FixtureNonce.BYTES) throw FixtureProviderError.InvalidNonce
    }

    private sealed class RequestState(open val file: File, open val expiresAtMillis: Long) {
        class Uploading(override val file: File, override val expiresAtMillis: Long) :
            RequestState(file, expiresAtMillis)

        class Ready(
            override val file: File,
            val input: FixtureCommandInput,
            override val expiresAtMillis: Long,
        ) : RequestState(file, expiresAtMillis)
    }

    class FixtureRequestUpload
    internal constructor(
        private val staging: FixtureRequestStaging,
        private val nonce: String,
        private val temporary: File,
    ) {
        fun writeFrom(source: InputStream) {
            try {
                FileOutputStream(temporary).use { output ->
                    output.write(FixtureRequestFiles.readBounded(source))
                    FixtureRequestFiles.sync(output)
                }
                staging.complete(nonce, temporary)
            } catch (failure: FixtureProviderError) {
                staging.abort(nonce, temporary)
                throw failure
            } catch (_: IOException) {
                staging.abort(nonce, temporary)
                throw FixtureProviderError.UploadInterrupted
            }
        }
    }

    class FixtureProxyUpload
    internal constructor(
        private val staging: FixtureRequestStaging,
        private val nonce: String,
        private val temporary: File,
    ) {
        private val output = staging.proxySinkFactory(temporary)
        private var position = 0L
        private var released = false

        @Synchronized
        fun writeAt(offset: Long, data: ByteArray, size: Int): Int {
            if (released || offset != position || size !in 0..data.size) {
                throw FixtureProviderError.UploadInterrupted
            }
            if (position + size > FIXTURE_MAXIMUM_REQUEST_BYTES) {
                throw FixtureProviderError.OversizedRequest
            }
            try {
                output.write(data, size)
            } catch (_: IOException) {
                throw FixtureProviderError.UploadInterrupted
            }
            position += size
            return size
        }

        @Synchronized
        fun sync() {
            if (released) throw FixtureProviderError.UploadInterrupted
            output.sync()
        }

        @Synchronized
        fun release() {
            if (released) return
            released = true
            var failure: FixtureProviderError? = null
            try {
                output.sync()
                staging.complete(nonce, temporary)
            } catch (caught: FixtureProviderError) {
                failure = caught
                staging.abort(nonce, temporary)
            } catch (_: IOException) {
                failure = FixtureProviderError.UploadInterrupted
                staging.abort(nonce, temporary)
            } finally {
                try {
                    output.close()
                } catch (_: IOException) {
                    if (failure == null) {
                        failure = FixtureProviderError.UploadInterrupted
                        staging.abort(nonce, temporary)
                    }
                }
            }
            failure?.let { throw it }
        }
    }

    private class RecentTokens {
        private val tokens = LinkedHashSet<String>()

        fun add(token: String) {
            tokens.add(token)
            if (tokens.size > MAXIMUM_TOKENS) tokens.remove(tokens.first())
        }

        operator fun contains(token: String): Boolean = token in tokens

        private companion object {
            const val MAXIMUM_TOKENS = 128
        }
    }

    companion object {
        const val UPLOAD_TTL_MILLIS = 30_000L
        private val NONCE = Regex("[A-Za-z0-9_-]{22}")
    }
}

data class FixtureStagingLimits(
    val uploadTtlMillis: Long = FixtureRequestStaging.UPLOAD_TTL_MILLIS,
    val executeWaitMillis: Long = 5_000L,
)
