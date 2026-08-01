package org.matrix.teesimulator.rkahost.evidence

import org.matrix.teesimulator.rkahost.cli.RootPrivateInput

data class CommandResult(val exitCode: Int, val stdout: String)

fun interface LiteralCommandRunner {
    fun run(argv: List<String>): CommandResult
}

class CommandRejected(message: String) : IllegalArgumentException(message)

data class CommandTrace(val argvHash: String, val operation: String) {
    fun canonical(): String = "$operation:$argvHash"
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
        validate(argv)
        runner.run(argv)
        return CommandTrace(EvidenceHash.sha256(argv.joinToString("\u0000")), "READ_ONLY")
    }

    private fun validate(argv: List<String>) {
        if (
            argv.size < 4 ||
                argv[0] != "adb" ||
                argv[1] != "-s" ||
                !argv[2].matches(Regex("[A-Za-z0-9._:-]{1,128}"))
        )
            throw CommandRejected("ADB_ARGV_INVALID")
        if (argv.any { it.any { character -> character in ";&|`$()<>\\\n\r\u0000" } })
            throw CommandRejected("ADB_SHELL_SMUGGLING")
        if (argv.drop(3).any { it in forbiddenWords })
            throw CommandRejected("ADB_FORBIDDEN_OPERATION")
        if (argv.size != 6 || argv[3] != "shell") throw CommandRejected("ADB_ARGV_INVALID")
        val verb = argv[4]
        if (verb != "getprop" || !properties.allows(argv[5]))
            throw CommandRejected("ADB_ARGV_NOT_ALLOWLISTED")
    }

    companion object {
        private val forbiddenWords = setOf("reboot", "kill", "pkill", "killall", "setprop", "svc")
    }
}
