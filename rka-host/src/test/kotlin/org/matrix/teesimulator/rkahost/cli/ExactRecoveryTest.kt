package org.matrix.teesimulator.rkahost.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactRecoveryTest {
    @Test
    fun rejectsAmbiguousSelectorWithoutMutation() {
        val transport = FakeRecoveryTransport(matches = 2)
        val error =
            assertThrows(ExactRecoveryException::class.java) {
                ExactRecoveryCli(transport).recover(RecoveryRole.DONOR, RecoveryTarget.RKPD)
            }
        assertEquals(ExactRecoveryFailure.MULTIPLE_MATCHES, error.failure)
        assertFalse(transport.mutations)
    }

    @Test
    fun rejectsBroadKill() {
        for (target in listOf("all", "*", "keystore", "rkpd keystore2")) {
            val transport = FakeRecoveryTransport()
            assertThrows(ExactRecoveryException::class.java) {
                ExactRecoveryCli.parseTarget(target)
            }
            assertFalse(transport.mutations)
        }
    }

    @Test
    fun exactRkpdRestartReappliesOnlySnapshottedEndpointProperties() {
        val transport = FakeRecoveryTransport(dropPropertiesOnRestart = true)
        val receipt = ExactRecoveryCli(transport).recover(RecoveryRole.DONOR, RecoveryTarget.RKPD)
        assertEquals("boot-A", receipt.bootId)
        assertTrue(receipt.quarantineRetained)
        assertEquals(
            setOf("remote_provisioning.hostname", "remote_provisioning.hostname_2"),
            transport.reapplied,
        )
        assertEquals(listOf(RecoveryTarget.RKPD), transport.restarts)
    }

    @Test
    fun zeroSelectorReadinessTimeoutBootAndPropertyDriftFailClosed() {
        val zero = FakeRecoveryTransport(matches = 0)
        assertThrows(ExactRecoveryException::class.java) {
            ExactRecoveryCli(zero).recover(RecoveryRole.DONOR, RecoveryTarget.KEYSTORE2)
        }
        assertFalse(zero.mutations)
        for (transport in
            listOf(
                FakeRecoveryTransport(ready = false),
                FakeRecoveryTransport(bootAfter = "boot-B"),
                FakeRecoveryTransport(quarantineAfter = false),
            )) {
            assertThrows(ExactRecoveryException::class.java) {
                ExactRecoveryCli(transport).recover(RecoveryRole.DONOR, RecoveryTarget.KEYSTORE2)
            }
        }
        assertThrows(ExactRecoveryException::class.java) {
            ExactRecoveryCli(FakeRecoveryTransport(propertyDrift = true))
                .recover(RecoveryRole.DONOR, RecoveryTarget.RKPD)
        }
    }
}

private class FakeRecoveryTransport(
    private val matches: Int = 1,
    private val ready: Boolean = true,
    private val bootAfter: String = "boot-A",
    private val propertyDrift: Boolean = false,
    private val quarantineAfter: Boolean = true,
    private val dropPropertiesOnRestart: Boolean = false,
) : ExactRecoveryTransport {
    var mutations = false
    val restarts = mutableListOf<RecoveryTarget>()
    val reapplied = mutableSetOf<String>()
    private val properties =
        linkedMapOf("remote_provisioning.hostname" to "a", "remote_provisioning.hostname_2" to "b")

    override fun snapshot(role: RecoveryRole, target: RecoveryTarget): RecoverySnapshot =
        RecoverySnapshot(
            bootId = "boot-A",
            uptimeMillis = 1_000,
            services =
                List(matches) {
                    RecoveryService(target, 100 + it, 500 + it.toLong(), target.executable)
                },
            properties = if (target == RecoveryTarget.RKPD) properties.toMap() else emptyMap(),
            quarantineRetained = true,
        )

    override fun restartExact(
        role: RecoveryRole,
        service: RecoveryService,
        target: RecoveryTarget,
    ) {
        mutations = true
        restarts += target
        if (dropPropertiesOnRestart) properties.replaceAll { _, _ -> "" }
    }

    override fun awaitReady(
        role: RecoveryRole,
        target: RecoveryTarget,
        deadlineMillis: Long,
    ): Boolean = ready

    override fun reapplyProperty(role: RecoveryRole, name: String, value: CharArray) {
        reapplied += name
        properties[name] = value.concatToString()
        value.fill('\u0000')
    }

    override fun verify(role: RecoveryRole, target: RecoveryTarget): RecoverySnapshot {
        val values =
            if (target == RecoveryTarget.RKPD) {
                if (propertyDrift) properties + ("remote_provisioning.hostname" to "drift")
                else properties.toMap()
            } else {
                emptyMap()
            }
        return snapshot(role, target)
            .copy(
                bootId = bootAfter,
                uptimeMillis = 1_100,
                properties = values,
                quarantineRetained = quarantineAfter,
            )
    }
}
