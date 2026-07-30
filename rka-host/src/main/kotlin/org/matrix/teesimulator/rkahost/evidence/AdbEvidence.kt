package org.matrix.teesimulator.rkahost.evidence

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

class AdbCommandPolicy(private val runner: LiteralCommandRunner) {
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
        if (verb != "getprop" || argv[5] !in allowedProperties)
            throw CommandRejected("ADB_ARGV_NOT_ALLOWLISTED")
    }

    companion object {
        private val allowedProperties =
            setOf(
                "ro.build.fingerprint",
                "ro.build.version.release",
                "ro.build.version.incremental",
                "ro.vendor.build.fingerprint",
            )
        private val forbiddenWords = setOf("reboot", "kill", "pkill", "killall", "setprop", "svc")
    }
}
