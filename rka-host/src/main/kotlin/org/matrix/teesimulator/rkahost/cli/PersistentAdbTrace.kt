package org.matrix.teesimulator.rkahost.cli

// allow: SIZE_OK — the hash-chain writer and strict parser share one canonical state machine.

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.matrix.teesimulator.rkahost.evidence.AdbCommandTracePolicy
import org.matrix.teesimulator.rkahost.evidence.CommandRejected

data class TraceBinding(
    val genesisSha256: String,
    val sessionId: String,
    val headSha256: String,
    val eventCount: Int,
)

data class ValidatedPersistentTrace(
    val canonical: ByteArray,
    val binding: TraceBinding,
    val verdict: String,
)

class PersistentAdbTrace
private constructor(private val path: Path, private val expected: Expected) {
    data class Expected(
        val pairSha256: String,
        val donorSha256: String,
        val candidateSha256: String,
        val sentinelId: String,
        val nonceSha256: String,
        val baselinePathSha256: String,
        val sessionId: String,
    )

    fun execute(argv: List<String>, block: () -> HostCommandResult): HostCommandResult {
        return executionLocked { executeLocked(argv, block) }
    }

    private fun executeLocked(
        argv: List<String>,
        block: () -> HostCommandResult,
    ): HostCommandResult {
        val operation = operation(argv)
        val boundSerial =
            argv.getOrNull(2)?.let { Hashes.sha256(it.toByteArray()) } in
                setOf(expected.donorSha256, expected.candidateSha256)
        val allowed =
            try {
                AdbCommandTracePolicy.requireAllowed(argv)
                boundSerial
            } catch (_: CommandRejected) {
                false
            }
        val start = append(operation, argv, if (allowed) "START" else "FORBIDDEN", null)
        if (!allowed) {
            append(operation, argv, "REJECTED", null, start)
            throw HostCliException(
                if (boundSerial) "ADB_FORBIDDEN_OPERATION" else "UNBOUND_DEVICE_COMMAND"
            )
        }
        return try {
            block().also {
                append(
                    operation,
                    argv,
                    if (it.exitCode == 0) "EXIT_OK" else "EXIT_NONZERO",
                    it.exitCode,
                    start,
                )
            }
        } catch (failure: HostCliException) {
            val status =
                when (failure.message) {
                    "ADB_START_FAILED" -> "START_FAILED"
                    "ADB_STDIN_FAILED" -> "STDIN_FAILED"
                    "ADB_TIMEOUT" -> "TIMEOUT"
                    else -> "CANCELLED"
                }
            append(operation, argv, status, null, start)
            throw failure
        }
    }

    private fun <T> executionLocked(block: () -> T): T {
        val lockPath = lockPathFor(path)
        requireSafe(lockPath)
        return synchronized(
            processLocks.computeIfAbsent(lockPath.toAbsolutePath().normalize()) { Any() }
        ) {
            FileChannel.open(lockPath, StandardOpenOption.READ, StandardOpenOption.WRITE).use {
                channel ->
                channel.lock().use { block() }
            }
        }
    }

    fun validateClean(): ValidatedPersistentTrace = locked { validate(it, false) }

    fun snapshotForReceipt(): ValidatedPersistentTrace = validateClean()

    private fun append(
        operation: String,
        argv: List<String>,
        status: String,
        exitCode: Int?,
        attempt: Int? = null,
    ): Int = locked { channel ->
        val current = validate(channel, attempt != null)
        if (current.verdict != "CLEAN" && attempt == null) {
            throw HostCliException("COMMAND_TRACE_DIRTY")
        }
        if (current.binding.eventCount >= MAX_EVENTS || current.canonical.size >= MAX_BYTES) {
            throw HostCliException("COMMAND_TRACE_LIMIT")
        }
        val sequence = current.binding.eventCount + 1
        val attemptSequence = attempt ?: sequence
        if ((attempt == null) != status.matches(Regex("START|FORBIDDEN"))) {
            throw HostCliException("COMMAND_TRACE_STATE_INVALID")
        }
        if (attempt != null && attempt != sequence - 1) {
            throw HostCliException("COMMAND_TRACE_STATE_INVALID")
        }
        val redacted = redact(argv)
        val argvHash = Hashes.sha256(argv.joinToString("\u0000").toByteArray())
        val body =
            listOf(
                    sequence.toString(),
                    attemptSequence.toString(),
                    operation,
                    redacted,
                    argvHash,
                    status,
                    exitCode?.toString() ?: "-",
                    current.binding.headSha256,
                )
                .joinToString("|")
        val line = "$body|${Hashes.sha256(body.toByteArray())}\n"
        val bytes = line.toByteArray()
        if (current.canonical.size + bytes.size > MAX_BYTES) {
            throw HostCliException("COMMAND_TRACE_LIMIT")
        }
        channel.position(channel.size())
        channel.write(ByteBuffer.wrap(bytes))
        channel.force(true)
        validate(channel, status.matches(Regex("START|FORBIDDEN")))
        sequence
    }

    private fun validate(channel: FileChannel, allowOrphan: Boolean): ValidatedPersistentTrace {
        if (channel.size() !in 1..MAX_BYTES.toLong())
            throw HostCliException("COMMAND_TRACE_INVALID")
        val raw = ByteArray(channel.size().toInt())
        channel.position(0)
        val buffer = ByteBuffer.wrap(raw)
        while (buffer.hasRemaining() && channel.read(buffer) > 0) {}
        if (buffer.hasRemaining()) throw HostCliException("COMMAND_TRACE_INVALID")
        return validateBytes(raw, expected, allowOrphan)
    }

    private fun <T> locked(block: (FileChannel) -> T): T {
        requireSafe(path)
        return synchronized(
            processLocks.computeIfAbsent(path.toAbsolutePath().normalize()) { Any() }
        ) {
            FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel
                ->
                channel.lock().use { block(channel) }
            }
        }
    }

    companion object {
        private val mode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        private val processLocks = ConcurrentHashMap<Path, Any>()
        private val eventPattern =
            Regex(
                "([1-9][0-9]*)\\|([1-9][0-9]*)\\|([A-Z0-9_-]{1,64})\\|([A-Za-z0-9_-]{1,8192})\\|([0-9a-f]{64})\\|(START|FORBIDDEN|REJECTED|EXIT_OK|EXIT_NONZERO|START_FAILED|STDIN_FAILED|TIMEOUT|CANCELLED)\\|(-|-?[0-9]{1,10})\\|([0-9a-f]{64})\\|([0-9a-f]{64})"
            )

        fun create(
            baselinePath: Path,
            pair: PairBinding,
            sentinelId: String,
            nonce: String,
        ): PersistentAdbTrace {
            val session = UUID.randomUUID().toString().replace("-", "")
            val expected =
                Expected(
                    pair.pairHash,
                    pair.donorSerialHash,
                    pair.candidateSerialHash,
                    sentinelId,
                    Hashes.sha256(nonce.toByteArray()),
                    baselinePathHash(baselinePath),
                    session,
                )
            val path = pathFor(baselinePath)
            val lockPath = lockPathFor(path)
            val parent = safeParent(path)
            if (
                Files.exists(path, LinkOption.NOFOLLOW_LINKS) ||
                    Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)
            )
                throw HostCliException("COMMAND_TRACE_EXISTS")
            val body = genesisBody(expected)
            val genesis = Hashes.sha256(body.toByteArray())
            val bytes = "$body|$genesis\n".toByteArray()
            val temporary = Files.createTempFile(parent, ".adb-trace-", ".tmp")
            try {
                Files.setPosixFilePermissions(temporary, mode)
                FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                    it.write(ByteBuffer.wrap(bytes))
                    it.force(true)
                }
                Files.move(temporary, path)
                Files.createFile(lockPath)
                Files.setPosixFilePermissions(lockPath, mode)
                FileChannel.open(lockPath, StandardOpenOption.WRITE).use { it.force(true) }
                FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
            } catch (_: Exception) {
                throw HostCliException("COMMAND_TRACE_CREATE_FAILED")
            } finally {
                Files.deleteIfExists(temporary)
            }
            return PersistentAdbTrace(path, expected).also { it.validateClean() }
        }

        fun open(baselinePath: Path, baseline: SentinelBaseline): PersistentAdbTrace {
            val expected =
                Expected(
                    baseline.binding.pairHash,
                    baseline.binding.donorSerialHash,
                    baseline.binding.candidateSerialHash,
                    baseline.sentinelId,
                    Hashes.sha256(baseline.nonce.toByteArray()),
                    baselinePathHash(baselinePath),
                    baseline.commandTraceSessionId,
                )
            return PersistentAdbTrace(pathFor(baselinePath), expected).also { it.validateClean() }
        }

        fun validateSnapshot(
            raw: ByteArray,
            baselinePath: Path,
            baseline: SentinelBaseline,
        ): ValidatedPersistentTrace =
            validateBytes(
                raw,
                Expected(
                    baseline.binding.pairHash,
                    baseline.binding.donorSerialHash,
                    baseline.binding.candidateSerialHash,
                    baseline.sentinelId,
                    Hashes.sha256(baseline.nonce.toByteArray()),
                    baselinePathHash(baselinePath),
                    baseline.commandTraceSessionId,
                ),
                false,
            )

        fun pathFor(baselinePath: Path): Path =
            baselinePath.resolveSibling(".${baselinePath.fileName}.adb-trace-v1")

        fun lockPathFor(tracePath: Path): Path =
            tracePath.resolveSibling("${tracePath.fileName}.lock")

        private fun validateBytes(
            raw: ByteArray,
            expected: Expected,
            allowOrphan: Boolean,
        ): ValidatedPersistentTrace {
            if (raw.size !in 1..MAX_BYTES || raw.last() != '\n'.code.toByte())
                throw HostCliException("COMMAND_TRACE_INVALID")
            val text = raw.toString(Charsets.UTF_8)
            if (!text.toByteArray().contentEquals(raw))
                throw HostCliException("COMMAND_TRACE_INVALID")
            val lines = text.dropLast(1).split('\n')
            if (lines.size > MAX_EVENTS + 1) throw HostCliException("COMMAND_TRACE_LIMIT")
            val expectedBody = genesisBody(expected)
            val expectedGenesis = Hashes.sha256(expectedBody.toByteArray())
            if (lines.firstOrNull() != "$expectedBody|$expectedGenesis")
                throw HostCliException("COMMAND_TRACE_BINDING_MISMATCH")
            var head = expectedGenesis
            var openAttempt: Int? = null
            var dirty = false
            lines.drop(1).forEachIndexed { index, line ->
                val values =
                    eventPattern.matchEntire(line)?.groupValues
                        ?: throw HostCliException("COMMAND_TRACE_INVALID")
                val sequence = index + 1
                if (values[1].toInt() != sequence || values[8] != head)
                    throw HostCliException("COMMAND_TRACE_CHAIN_MISMATCH")
                val body = values.subList(1, 9).joinToString("|")
                if (Hashes.sha256(body.toByteArray()) != values[9])
                    throw HostCliException("COMMAND_TRACE_CHAIN_MISMATCH")
                val status = values[6]
                if (status == "START" || status == "FORBIDDEN") {
                    if (openAttempt != null || values[2].toInt() != sequence)
                        throw HostCliException("COMMAND_TRACE_STATE_INVALID")
                    openAttempt = sequence
                    if (status == "FORBIDDEN") dirty = true
                } else {
                    if (openAttempt == null || values[2].toInt() != openAttempt)
                        throw HostCliException("COMMAND_TRACE_STATE_INVALID")
                    openAttempt = null
                    if (status != "EXIT_OK" && status != "EXIT_NONZERO") dirty = true
                }
                head = values[9]
            }
            if (openAttempt != null && !allowOrphan)
                throw HostCliException("COMMAND_TRACE_INCOMPLETE")
            return ValidatedPersistentTrace(
                raw,
                TraceBinding(expectedGenesis, expected.sessionId, head, lines.size - 1),
                if (dirty || openAttempt != null) "DIRTY" else "CLEAN",
            )
        }

        private fun genesisBody(value: Expected): String =
            listOf(
                    "RKA_ADB_TRACE_V1",
                    value.pairSha256,
                    value.donorSha256,
                    value.candidateSha256,
                    value.sentinelId,
                    value.nonceSha256,
                    value.sessionId,
                    AdbCommandTracePolicy.policySha256,
                    value.baselinePathSha256,
                )
                .joinToString("|")

        private fun baselinePathHash(path: Path): String =
            Hashes.sha256(path.toAbsolutePath().normalize().toString().toByteArray())

        private fun operation(argv: List<String>): String =
            argv
                .drop(3)
                .take(2)
                .joinToString("_")
                .uppercase()
                .replace(Regex("[^A-Z0-9_-]"), "_")
                .take(64)
                .ifEmpty { "ADB" }

        private fun redact(argv: List<String>): String {
            if (argv.size !in 4..128 || argv.any { it.toByteArray().size !in 1..4096 })
                throw HostCliException("ADB_ARGV_INVALID")
            val values = argv.toMutableList()
            values[2] = "SERIAL_SHA256:${Hashes.sha256(argv[2].toByteArray())}"
            return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(values.joinToString("\u0000").toByteArray())
        }

        private fun requireSafe(path: Path) {
            if (
                Files.isSymbolicLink(path) ||
                    !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                    Files.getPosixFilePermissions(path) != mode
            )
                throw HostCliException("COMMAND_TRACE_PATH_UNSAFE")
        }

        private fun safeParent(path: Path): Path {
            val parent =
                path.toAbsolutePath().parent ?: throw HostCliException("COMMAND_TRACE_PATH_UNSAFE")
            if (
                Files.isSymbolicLink(parent) ||
                    !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
            )
                throw HostCliException("COMMAND_TRACE_PATH_UNSAFE")
            return parent
        }

        private const val MAX_EVENTS = 20_000
        private const val MAX_BYTES = 8 * 1024 * 1024
    }
}

class TracedHostCommandRunner(
    private val delegate: HostCommandRunner,
    private val trace: PersistentAdbTrace,
) : HostCommandRunner {
    override fun run(argv: List<String>): HostCommandResult =
        trace.execute(argv) { delegate.run(argv) }

    override fun runRoot(
        serial: BoundSerial,
        script: String,
        arguments: List<String>,
        privateInput: RootPrivateInput,
    ): HostCommandResult =
        trace.execute(listOf("adb", "-s", serial.value, "shell", "su", "0", "sh")) {
            delegate.runRoot(serial, script, arguments, privateInput)
        }
}

object TraceContextStore {
    private val mode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    fun write(runtime: Path, baselinePath: Path, baseline: SentinelBaseline) {
        val path = path(runtime)
        val parent = runtime.toAbsolutePath()
        if (Files.isSymbolicLink(parent) || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("TRACE_CONTEXT_PATH_UNSAFE")
        }
        val encoded =
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(baselinePath.toAbsolutePath().normalize().toString().toByteArray())
        val value = "$encoded|${baseline.binding.pairHash}|${baseline.commandTraceSessionId}\n"
        val temporary = Files.createTempFile(parent, ".trace-context-", ".tmp")
        try {
            Files.setPosixFilePermissions(temporary, mode)
            FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                it.write(ByteBuffer.wrap(value.toByteArray()))
                it.force(true)
            }
            Files.move(
                temporary,
                path,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
            FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    fun read(runtime: Path, pair: PairBinding): Pair<Path, SentinelBaseline>? {
        val path = path(runtime)
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) return null
        requireSafe(path)
        val values = Files.readString(path).removeSuffix("\n").split('|')
        if (values.size != 3 || !Files.readString(path).endsWith('\n'))
            throw HostCliException("TRACE_CONTEXT_INVALID")
        val baselinePath =
            try {
                Path.of(Base64.getUrlDecoder().decode(values[0]).toString(Charsets.UTF_8))
            } catch (_: Exception) {
                throw HostCliException("TRACE_CONTEXT_INVALID")
            }
        val baseline = BaselineStore.read(baselinePath)
        if (
            baseline.binding != pair ||
                values[1] != pair.pairHash ||
                values[2] != baseline.commandTraceSessionId
        ) {
            throw HostCliException("PAIR_BINDING_MISMATCH")
        }
        PersistentAdbTrace.open(baselinePath, baseline).validateClean()
        return baselinePath to baseline
    }

    fun delete(runtime: Path) {
        val path = path(runtime)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) requireSafe(path)
        Files.deleteIfExists(path)
        FileChannel.open(runtime.toAbsolutePath(), StandardOpenOption.READ).use { it.force(true) }
    }

    private fun path(runtime: Path): Path = runtime.resolve("active-adb-trace-v1")

    private fun requireSafe(path: Path) {
        if (
            Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                Files.getPosixFilePermissions(path) != mode
        ) {
            throw HostCliException("TRACE_CONTEXT_PATH_UNSAFE")
        }
    }
}
