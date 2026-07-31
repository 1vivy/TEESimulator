package org.matrix.teesimulator.rkahost.cli

import java.util.Base64

enum class RecoveryRole {
    DONOR,
    CANDIDATE,
}

enum class RecoveryTarget(val executable: String) {
    KEYSTORE2("/system/bin/keystore2"),
    RKPD("/system/bin/rkpd"),
}

data class RecoveryService(
    val target: RecoveryTarget,
    val pid: Int,
    val startTimeTicks: Long,
    val executable: String,
) {
    init {
        require(pid > 0 && startTimeTicks > 0)
        require(executable == target.executable)
    }
}

data class RecoverySnapshot(
    val bootId: String,
    val uptimeMillis: Long,
    val services: List<RecoveryService>,
    val properties: Map<String, String>,
    val sentinelHash: String,
    val quarantineCount: Int,
    val quarantineHash: String,
)

data class ExactRecoveryReceipt(
    val bootId: String,
    val propertyHash: String,
    val quarantineRetained: Boolean,
)

interface ExactRecoveryTransport {
    fun snapshot(role: RecoveryRole, target: RecoveryTarget): RecoverySnapshot

    fun restartExact(role: RecoveryRole, service: RecoveryService, target: RecoveryTarget)

    fun awaitReady(role: RecoveryRole, target: RecoveryTarget, deadlineMillis: Long): Boolean

    fun reapplyProperty(role: RecoveryRole, name: String, value: CharArray)

    fun verify(role: RecoveryRole, target: RecoveryTarget): RecoverySnapshot
}

enum class ExactRecoveryFailure {
    TARGET_INVALID,
    ROLE_INVALID,
    ZERO_MATCHES,
    MULTIPLE_MATCHES,
    SERVICE_IDENTITY_DRIFT,
    READINESS_TIMEOUT,
    BOOT_ID_DRIFT,
    UPTIME_DRIFT,
    PROPERTY_DRIFT,
    SENTINEL_DRIFT,
    QUARANTINE_LOST,
    QUARANTINE_DRIFT,
    SNAPSHOT_INVALID,
}

class ExactRecoveryException(val failure: ExactRecoveryFailure) :
    IllegalStateException("EXACT_RECOVERY_${failure.name}")

class ExactRecoveryCli(private val transport: ExactRecoveryTransport) {
    fun recover(role: RecoveryRole, target: RecoveryTarget): ExactRecoveryReceipt {
        if (target == RecoveryTarget.RKPD && role != RecoveryRole.DONOR) {
            fail(ExactRecoveryFailure.ROLE_INVALID)
        }
        val before = transport.snapshot(role, target)
        validateSnapshot(before, role, target)
        val service = select(before.services, target)
        val propertyHash = propertyHash(before.properties)
        transport.restartExact(role, service, target)
        if (!transport.awaitReady(role, target, READINESS_DEADLINE_MILLIS)) {
            fail(ExactRecoveryFailure.READINESS_TIMEOUT)
        }
        var after = transport.verify(role, target)
        if (target == RecoveryTarget.RKPD && after.properties != before.properties) {
            reapplyLostRkpdProperties(role, before.properties, after.properties)
            after = transport.verify(role, target)
        }
        if (after.bootId != before.bootId) fail(ExactRecoveryFailure.BOOT_ID_DRIFT)
        if (after.uptimeMillis <= before.uptimeMillis) fail(ExactRecoveryFailure.UPTIME_DRIFT)
        if (propertyHash(after.properties) != propertyHash) {
            fail(ExactRecoveryFailure.PROPERTY_DRIFT)
        }
        if (after.sentinelHash != before.sentinelHash) fail(ExactRecoveryFailure.SENTINEL_DRIFT)
        if (after.quarantineCount <= 0) fail(ExactRecoveryFailure.QUARANTINE_LOST)
        if (
            after.quarantineCount != before.quarantineCount ||
                after.quarantineHash != before.quarantineHash
        ) {
            fail(ExactRecoveryFailure.QUARANTINE_DRIFT)
        }
        validateSnapshot(after, role, target)
        select(after.services, target)
        return ExactRecoveryReceipt(before.bootId, propertyHash, true)
    }

    private fun validateSnapshot(
        snapshot: RecoverySnapshot,
        role: RecoveryRole,
        target: RecoveryTarget,
    ) {
        if (
            !snapshot.bootId.matches(Regex("[A-Za-z0-9._-]{1,128}")) ||
                snapshot.uptimeMillis < 0 ||
                !snapshot.sentinelHash.matches(Regex("[0-9a-f]{64}")) ||
                snapshot.quarantineCount !in 1..20 ||
                !snapshot.quarantineHash.matches(Regex("[0-9a-f]{64}")) ||
                snapshot.properties.keys.any { !it.matches(Regex("[a-zA-Z0-9_.-]{1,128}")) } ||
                snapshot.properties.values.any { it.contains('\n') || it.contains('\u0000') }
        ) {
            fail(ExactRecoveryFailure.SNAPSHOT_INVALID)
        }
        if (target == RecoveryTarget.RKPD && role == RecoveryRole.DONOR) {
            if (snapshot.properties.size != 2) fail(ExactRecoveryFailure.SNAPSHOT_INVALID)
        }
    }

    private fun select(services: List<RecoveryService>, target: RecoveryTarget): RecoveryService {
        val matches = services.filter { it.target == target && it.executable == target.executable }
        return when (matches.size) {
            0 -> fail(ExactRecoveryFailure.ZERO_MATCHES)
            1 -> matches.single()
            else -> fail(ExactRecoveryFailure.MULTIPLE_MATCHES)
        }
    }

    private fun reapplyLostRkpdProperties(
        role: RecoveryRole,
        before: Map<String, String>,
        after: Map<String, String>,
    ) {
        if (before.keys != after.keys) fail(ExactRecoveryFailure.PROPERTY_DRIFT)
        before.forEach { (name, original) ->
            val current = after.getValue(name)
            if (current.isNotEmpty() && current != original) {
                fail(ExactRecoveryFailure.PROPERTY_DRIFT)
            }
            if (current.isEmpty()) {
                val value = original.toCharArray()
                try {
                    transport.reapplyProperty(role, name, value)
                } finally {
                    value.fill('\u0000')
                }
            }
        }
    }

    private fun propertyHash(properties: Map<String, String>): String =
        Hashes.sha256(
            properties
                .toSortedMap()
                .entries
                .joinToString("\n") { (name, value) ->
                    "$name=${Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())}"
                }
                .toByteArray()
        )

    private fun fail(failure: ExactRecoveryFailure): Nothing = throw ExactRecoveryException(failure)

    companion object {
        private const val READINESS_DEADLINE_MILLIS = 5_000L

        fun parseTarget(value: String): RecoveryTarget =
            when (value) {
                "keystore2" -> RecoveryTarget.KEYSTORE2
                "rkpd" -> RecoveryTarget.RKPD
                else -> throw ExactRecoveryException(ExactRecoveryFailure.TARGET_INVALID)
            }

        fun parseRole(value: String): RecoveryRole =
            when (value) {
                "donor" -> RecoveryRole.DONOR
                "candidate" -> RecoveryRole.CANDIDATE
                else -> throw ExactRecoveryException(ExactRecoveryFailure.ROLE_INVALID)
            }
    }
}

internal class ControlScriptRecoveryTransport(
    private val pair: DevicePairSnapshot,
    private val invoke: (List<String>) -> HostCommandResult,
) : ExactRecoveryTransport {
    override fun snapshot(role: RecoveryRole, target: RecoveryTarget): RecoverySnapshot =
        query(role, target, "snapshot")

    override fun restartExact(
        role: RecoveryRole,
        service: RecoveryService,
        target: RecoveryTarget,
    ) {
        command(role, "restart", target, service.pid.toString(), service.startTimeTicks.toString())
    }

    override fun awaitReady(
        role: RecoveryRole,
        target: RecoveryTarget,
        deadlineMillis: Long,
    ): Boolean = command(role, "ready", target, deadlineMillis.toString()).stdout.trim() == "READY"

    override fun reapplyProperty(role: RecoveryRole, name: String, value: CharArray) {
        command(role, "reapply", RecoveryTarget.RKPD, name)
    }

    override fun verify(role: RecoveryRole, target: RecoveryTarget): RecoverySnapshot =
        query(role, target, "verify")

    private fun query(
        role: RecoveryRole,
        target: RecoveryTarget,
        action: String,
    ): RecoverySnapshot {
        val fields =
            command(role, action, target)
                .stdout
                .lineSequence()
                .filter(String::isNotBlank)
                .map {
                    val delimiter = it.indexOf('=')
                    if (delimiter <= 0) throw HostCliException("RECOVERY_SNAPSHOT_INVALID")
                    it.substring(0, delimiter) to it.substring(delimiter + 1)
                }
                .groupBy({ it.first }, { it.second })
        val properties =
            fields["property"].orEmpty().associate {
                val delimiter = it.indexOf('|')
                if (delimiter <= 0) throw HostCliException("RECOVERY_SNAPSHOT_INVALID")
                it.substring(0, delimiter) to
                    Base64.getUrlDecoder()
                        .decode(it.substring(delimiter + 1))
                        .toString(Charsets.UTF_8)
            }
        val services =
            fields["service"].orEmpty().map {
                val parts = it.split('|')
                if (parts.size != 4) throw HostCliException("RECOVERY_SNAPSHOT_INVALID")
                RecoveryService(
                    ExactRecoveryCli.parseTarget(parts[0]),
                    parts[1].toInt(),
                    parts[2].toLong(),
                    parts[3],
                )
            }
        return RecoverySnapshot(
            fields.getValue("boot_id").single(),
            fields.getValue("uptime_ms").single().toLong(),
            services,
            properties,
            fields.getValue("sentinel_hash").single(),
            fields.getValue("quarantine_count").single().toInt(),
            fields.getValue("quarantine_hash").single(),
        )
    }

    private fun command(
        role: RecoveryRole,
        action: String,
        target: RecoveryTarget,
        vararg arguments: String,
    ): HostCommandResult =
        invoke(
            listOf(
                "adb",
                "-s",
                serial(role).value,
                "shell",
                "sh",
                RKA_CONTROL_PATH,
                "recover-exact",
                action,
                target.name.lowercase(),
            ) + arguments
        )

    private fun serial(role: RecoveryRole): BoundSerial =
        when (role) {
            RecoveryRole.DONOR -> pair.donor
            RecoveryRole.CANDIDATE -> pair.candidate
        }
}
