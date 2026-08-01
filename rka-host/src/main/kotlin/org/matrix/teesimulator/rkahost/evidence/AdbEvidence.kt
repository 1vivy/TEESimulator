package org.matrix.teesimulator.rkahost.evidence

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import org.matrix.teesimulator.rkahost.cli.RootPrivateInput

data class CommandResult(val exitCode: Int, val stdout: String)

fun interface LiteralCommandRunner {
    fun run(argv: List<String>): CommandResult
}

class CommandRejected(message: String) : IllegalArgumentException(message)

data class CommandTrace(val argvHash: String, val operation: String) {
    fun canonical(): String = "$operation:$argvHash"
}

enum class CommandTraceVerdict {
    CLEAN
}

data class ValidatedCommandTrace(
    val encoded: ByteArray,
    val policySha256: String,
    val traceSha256: String,
    val verdict: CommandTraceVerdict,
)

object AdbCommandTracePolicy {
    private val forbiddenCommands = setOf("reboot", "kill", "pkill", "killall", "setprop", "svc")
    private val directServiceCommands = setOf("start", "stop")
    private val commandFragment = Regex("[A-Za-z0-9_./:-]+")

    val policySha256: String =
        EvidenceHash.sha256(
            "version=1\n" +
                "transport=adb-bound-serial\n" +
                "forbidden=${forbiddenCommands.sorted().joinToString(",")}\n" +
                "direct-service=${directServiceCommands.sorted().joinToString(",")}\n" +
                "shell-smuggling=true\n" +
                "tokenizer=lowercase-basename-contiguous-fragments\n" +
                "bounds=$MAX_COMMANDS:$MAX_ARGUMENTS:$MAX_TOKEN_BYTES\n"
        )

    fun requireAllowed(argv: List<String>) {
        if (
            argv.size < 4 ||
                argv[0] != "adb" ||
                argv[1] != "-s" ||
                !argv[2].matches(Regex("[A-Za-z0-9._:-]{1,128}"))
        ) {
            throw CommandRejected("ADB_ARGV_INVALID")
        }
        if (argv.any { it.any { character -> character in ";&|`$()<>\\\n\r\u0000" } }) {
            throw CommandRejected("ADB_SHELL_SMUGGLING")
        }
        val tokens = argv.drop(3).flatMap(::commandTokens)
        if (containsForbiddenCommand(tokens)) {
            throw CommandRejected("ADB_FORBIDDEN_OPERATION")
        }
        if (
            argv[3] == "shell" &&
                argv.getOrNull(4)?.let(::commandTokens)?.firstOrNull() in directServiceCommands
        ) {
            throw CommandRejected("ADB_FORBIDDEN_OPERATION")
        }
    }

    fun issue(trace: List<List<String>>): ValidatedCommandTrace {
        if (trace.isEmpty()) throw CommandRejected("COMMAND_TRACE_MISSING")
        if (trace.size > MAX_COMMANDS) throw CommandRejected("COMMAND_TRACE_INVALID")
        trace.forEach { argv ->
            if (argv.size !in 1..MAX_ARGUMENTS) throw CommandRejected("COMMAND_TRACE_INVALID")
            requireAllowed(argv)
        }
        val encoded = encode(trace)
        return ValidatedCommandTrace(
            encoded,
            policySha256,
            EvidenceHash.sha256(encoded),
            CommandTraceVerdict.CLEAN,
        )
    }

    fun verify(encoded: ByteArray, expectedTraceSha256: String): ValidatedCommandTrace {
        val validated = issue(decode(encoded))
        if (!validated.encoded.contentEquals(encoded)) {
            throw CommandRejected("COMMAND_TRACE_INVALID")
        }
        if (validated.traceSha256 != expectedTraceSha256) {
            throw CommandRejected("COMMAND_TRACE_MISMATCH")
        }
        return validated
    }

    private fun commandTokens(raw: String): List<String> =
        commandFragment
            .findAll(raw)
            .map { it.value.substringAfterLast('/').lowercase() }
            .filter(String::isNotEmpty)
            .toList()

    private fun containsForbiddenCommand(tokens: List<String>): Boolean {
        tokens.indices.forEach { start ->
            val candidate = StringBuilder()
            for (token in tokens.drop(start)) {
                candidate.append(token)
                if (candidate.length > MAX_FORBIDDEN_COMMAND_BYTES) break
                if (candidate.toString() in forbiddenCommands) return true
            }
        }
        return false
    }

    private fun encode(trace: List<List<String>>): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(trace.size)
                trace.forEach { argv ->
                    output.writeInt(argv.size)
                    argv.forEach { value ->
                        val token = value.toByteArray(Charsets.UTF_8)
                        if (token.size !in 1..MAX_TOKEN_BYTES) {
                            throw CommandRejected("COMMAND_TRACE_INVALID")
                        }
                        output.writeInt(token.size)
                        output.write(token)
                    }
                }
            }
            bytes.toByteArray()
        }

    private fun decode(raw: ByteArray): List<List<String>> =
        try {
            DataInputStream(raw.inputStream()).use { input ->
                val count = input.readInt()
                if (count !in 1..MAX_COMMANDS) throw CommandRejected("COMMAND_TRACE_INVALID")
                List(count) {
                        val arguments = input.readInt()
                        if (arguments !in 1..MAX_ARGUMENTS) {
                            throw CommandRejected("COMMAND_TRACE_INVALID")
                        }
                        List(arguments) {
                            val size = input.readInt()
                            if (size !in 1..MAX_TOKEN_BYTES) {
                                throw CommandRejected("COMMAND_TRACE_INVALID")
                            }
                            val token = input.readNBytes(size)
                            if (token.size != size) throw CommandRejected("COMMAND_TRACE_INVALID")
                            token.toString(Charsets.UTF_8).also {
                                if (!it.toByteArray(Charsets.UTF_8).contentEquals(token)) {
                                    throw CommandRejected("COMMAND_TRACE_INVALID")
                                }
                            }
                        }
                    }
                    .also { if (input.read() != -1) throw CommandRejected("COMMAND_TRACE_INVALID") }
            }
        } catch (failure: CommandRejected) {
            throw failure
        } catch (_: Exception) {
            throw CommandRejected("COMMAND_TRACE_INVALID")
        }

    private const val MAX_COMMANDS = 10_000
    private const val MAX_ARGUMENTS = 128
    private const val MAX_TOKEN_BYTES = 65_536
    private const val MAX_FORBIDDEN_COMMAND_BYTES = 7
}

enum class FutureServiceOperation(val executed: Boolean) {
    KEYSTORE2_STATUS(false),
    RKPD_STATUS(false),
}

class PropertyAllowlist private constructor(private val names: Set<String>) {
    fun allows(name: String): Boolean = name in names

    fun validate(properties: Map<String, String>) {
        require(properties.keys.all { allows(it) && !SECRET_WORDS.containsMatchIn(it) }) {
            "PROPERTY_NOT_ALLOWLISTED"
        }
        require(properties.values.none { it.contains('\n') || it.contains('\u0000') }) {
            "PROPERTY_VALUE_INVALID"
        }
    }

    fun privateInput(): RootPrivateInput = RootPrivateInput.parse(names.toList())

    companion object {
        fun parse(names: List<String>): PropertyAllowlist {
            RootPrivateInput.parse(names)
            require(names.isNotEmpty() && names.distinct().size == names.size) {
                "PROPERTY_ALLOWLIST_INVALID"
            }
            return PropertyAllowlist(names.toSet())
        }

        private val SECRET_WORDS =
            Regex("(?i)(secret|token|password|credential|key|alias|blob|private|auth)")
    }
}

private val donorPropertyAllowlist =
    PropertyAllowlist.parse(
        listOf(
            "ro.build.fingerprint",
            "ro.build.version.release",
            "ro.build.version.incremental",
            "ro.vendor.build.fingerprint",
        )
    )

internal fun donorPropertyPrivateInput(): RootPrivateInput = donorPropertyAllowlist.privateInput()

internal fun validateDonorProperties(properties: Map<String, String>) =
    donorPropertyAllowlist.validate(properties)

class AdbCommandPolicy(
    private val runner: LiteralCommandRunner,
    private val properties: PropertyAllowlist = donorPropertyAllowlist,
) {
    fun execute(argv: List<String>): CommandTrace {
        AdbCommandTracePolicy.requireAllowed(argv)
        validateReadOnly(argv)
        if (runner.run(argv).exitCode != 0) throw CommandRejected("ADB_COMMAND_FAILED")
        return CommandTrace(EvidenceHash.sha256(argv.joinToString("\u0000")), "READ_ONLY")
    }

    private fun validateReadOnly(argv: List<String>) {
        if (argv.size != 6 || argv[3] != "shell") throw CommandRejected("ADB_ARGV_INVALID")
        val verb = argv[4]
        if (verb != "getprop" || !properties.allows(argv[5]))
            throw CommandRejected("ADB_ARGV_NOT_ALLOWLISTED")
    }
}
