package org.matrix.teesimulator.rkahost

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

enum class DeviceRole {
    DONOR,
    CANDIDATE,
}

class DeviceSerial private constructor(val role: DeviceRole, val value: String) {
    companion object {
        private val serialPattern = Regex("[A-Za-z0-9._:-]{1,128}")

        fun of(role: DeviceRole, value: String): DeviceSerial {
            require(serialPattern.matches(value)) { "ROLE_SERIAL_MISMATCH" }
            return DeviceSerial(role, value)
        }

        fun requirePair(donor: DeviceSerial, candidate: DeviceSerial) {
            require(donor.role == DeviceRole.DONOR) { "ROLE_SERIAL_MISMATCH" }
            require(candidate.role == DeviceRole.CANDIDATE) { "ROLE_SERIAL_MISMATCH" }
            require(donor.value != candidate.value) { "ROLE_SERIAL_MISMATCH" }
        }
    }
}

enum class DiagnosticTransportKind {
    DIAGNOSTIC_USB_RELAY
}

data class AdbResult(val exitCode: Int, val stdout: ByteArray, val stderr: ByteArray = ByteArray(0))

fun interface AdbCommandRunner {
    @Throws(InterruptedException::class)
    fun run(argv: List<String>, stdin: ByteArray, timeout: Duration): AdbResult
}

class ProviderCommandException(message: String) : RuntimeException(message)

class ProviderTimeoutException(message: String) : RuntimeException(message)

class ProviderOutputTooLargeException : RuntimeException("PROVIDER_OUTPUT_TOO_LARGE")

class ProviderProtocolException(message: String) : RuntimeException(message)

class ProcessAdbRunner(private val adbPath: String = "adb") : AdbCommandRunner {
    override fun run(argv: List<String>, stdin: ByteArray, timeout: Duration): AdbResult {
        require(argv.isNotEmpty() && argv.first() == adbPath) { "ADB_ARGV_INVALID" }
        require(argv.none { it.contains('\u0000') }) { "ADB_ARGV_INVALID" }
        require(!timeout.isZero && !timeout.isNegative) { "ADB_TIMEOUT_INVALID" }

        val process = ProcessBuilder(argv).start()
        val workers = Executors.newFixedThreadPool(3)
        try {
            val stdinFuture =
                workers.submit(Callable { process.outputStream.use { it.write(stdin) } })
            val stdoutFuture = workers.submit(Callable { process.inputStream.readBounded() })
            val stderrFuture = workers.submit(Callable { process.errorStream.readBounded() })
            val deadline = System.nanoTime() + timeout.toNanos()
            while (!process.waitFor(20, TimeUnit.MILLISECONDS)) {
                failIfDone(stdinFuture)
                failIfDone(stdoutFuture)
                failIfDone(stderrFuture)
                if (System.nanoTime() >= deadline) {
                    throw ProviderTimeoutException("ADB_TIMEOUT")
                }
            }
            failIfDone(stdinFuture)
            return AdbResult(process.exitValue(), stdoutFuture.await(), stderrFuture.await())
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        } finally {
            process.destroyForcibly()
            workers.shutdownNow()
        }
    }

    private fun InputStream.readBounded(): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = read(buffer)
            if (count < 0) return output.toByteArray()
            if (output.size() + count > FixtureProviderClient.MAX_PROVIDER_RESPONSE_BYTES) {
                throw ProviderOutputTooLargeException()
            }
            output.write(buffer, 0, count)
        }
    }

    private fun failIfDone(future: Future<*>) {
        if (future.isDone) future.await()
    }

    private fun <T> Future<T>.await(): T =
        try {
            get()
        } catch (failure: ExecutionException) {
            throw (failure.cause ?: failure)
        }
}

class FixtureProviderClient(
    private val donor: DeviceSerial,
    private val runner: AdbCommandRunner,
    private val nonceSource: () -> ByteArray = {
        java.security.SecureRandom().generateSeed(NONCE_BYTES)
    },
    private val timeout: Duration = Duration.ofSeconds(30),
) {
    init {
        require(donor.role == DeviceRole.DONOR) { "ROLE_SERIAL_MISMATCH" }
    }

    fun exchange(request: ByteArray): ByteArray {
        val nonce = nonceSource()
        require(nonce.size == NONCE_BYTES) { "NONCE_LENGTH_INVALID" }
        val nonceHex = nonce.joinToString("") { "%02x".format(it) }
        val requestUri = "$AUTHORITY/v1/request/$nonceHex"
        val executeUri = "$AUTHORITY/v1/execute/$nonceHex"
        var primary: Throwable? = null
        var interruption: InterruptedException? = null
        try {
            runContent("write", requestUri, request)
            val response = runContent("read", executeUri, ByteArray(0))
            return FixtureResponse.decode(response, nonce)
        } catch (interrupted: InterruptedException) {
            interruption = interrupted
            primary = interrupted
            throw interrupted
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            try {
                runContent("delete", requestUri, ByteArray(0))
            } catch (cleanup: Throwable) {
                primary?.addSuppressed(cleanup) ?: throw cleanup
            } finally {
                if (interruption != null) Thread.currentThread().interrupt()
            }
        }
    }

    private fun runContent(verb: String, uri: String, stdin: ByteArray): ByteArray {
        val result =
            runner.run(
                listOf("adb", "-s", donor.value, "shell", "content", verb, "--uri", uri),
                stdin,
                timeout,
            )
        if (result.exitCode != 0)
            throw ProviderCommandException("CONTENT_${verb.uppercase()}_FAILED")
        if (result.stdout.size > MAX_PROVIDER_RESPONSE_BYTES)
            throw ProviderOutputTooLargeException()
        return result.stdout
    }

    companion object {
        const val AUTHORITY = "content://org.matrix.teesimulator.rkafixture.commands"
        const val NONCE_BYTES = 16
        const val MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024
    }
}

object FixtureResponse {
    private val magic =
        byteArrayOf('R'.code.toByte(), 'K'.code.toByte(), 'A'.code.toByte(), '2'.code.toByte())

    fun encode(nonce: ByteArray, payload: ByteArray): ByteArray {
        require(nonce.size == FixtureProviderClient.NONCE_BYTES) { "NONCE_LENGTH_INVALID" }
        require(
            payload.size <=
                FixtureProviderClient.MAX_PROVIDER_RESPONSE_BYTES - magic.size - nonce.size
        ) {
            "PROVIDER_OUTPUT_TOO_LARGE"
        }
        return magic + nonce + payload
    }

    fun decode(response: ByteArray, expectedNonce: ByteArray): ByteArray {
        if (response.size > FixtureProviderClient.MAX_PROVIDER_RESPONSE_BYTES)
            throw ProviderOutputTooLargeException()
        if (response.size < magic.size + FixtureProviderClient.NONCE_BYTES) {
            throw ProviderProtocolException("PROVIDER_RESPONSE_FRAMING_INVALID")
        }
        if (!response.copyOfRange(0, magic.size).contentEquals(magic)) {
            throw ProviderProtocolException("PROVIDER_RESPONSE_FRAMING_INVALID")
        }
        val actualNonce =
            response.copyOfRange(magic.size, magic.size + FixtureProviderClient.NONCE_BYTES)
        if (!actualNonce.contentEquals(expectedNonce))
            throw ProviderProtocolException("PROVIDER_NONCE_MISMATCH")
        return response.copyOfRange(magic.size + FixtureProviderClient.NONCE_BYTES, response.size)
    }
}

class UsbHostRelayTransport(
    donor: DeviceSerial,
    candidate: DeviceSerial,
    runner: AdbCommandRunner,
    nonceSource: () -> ByteArray = {
        java.security.SecureRandom().generateSeed(FixtureProviderClient.NONCE_BYTES)
    },
    timeout: Duration = Duration.ofSeconds(30),
) {
    val kind: DiagnosticTransportKind = DiagnosticTransportKind.DIAGNOSTIC_USB_RELAY
    private val fixture = FixtureProviderClient(donor, runner, nonceSource, timeout)

    init {
        DeviceSerial.requirePair(donor, candidate)
    }

    fun exchange(request: ByteArray): ByteArray = fixture.exchange(request)
}
