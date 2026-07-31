package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NoRebootDeployCommandContractTest {
    private val script =
        Files.readString(
            Path.of(System.getProperty("user.dir")).parent.resolve("scripts/rka-deploy.sh")
        )

    @Test
    fun transactionOrdersBothSnapshotsAndOldRuntimeRemovalBeforeSingleInstall() {
        val deploy = script.substringAfter("deploy)\n").substringBefore("    ;;\npair)")
        val activeSnapshot = deploy.indexOf("tree_hash \"\$active\" > \"\$txn/active.before\"")
        val pendingSnapshot = deploy.indexOf("tree_hash \"\$pending\" > \"\$txn/pending.before\"")
        val pendingPreserve = deploy.indexOf("mv \"\$pending\" \"\$txn/pending.tree\"")
        val stop = deploy.indexOf("\"\$active/rka-control.sh\" stop")
        val unmount = deploy.indexOf("nsenter -t 1 -m -- umount \"\$active\"")
        val install = deploy.indexOf("ksud module install \"\$archive\"")

        assertTrue(activeSnapshot >= 0 && pendingSnapshot > activeSnapshot)
        assertTrue(stop > pendingSnapshot && unmount > stop)
        assertTrue(pendingPreserve > unmount && install > pendingPreserve)
        assertEquals(1, Regex("ksud module install").findAll(deploy).count())
    }

    @Test
    fun policyBindAndActiveViewStartAreStrictlyOrdered() {
        val deploy = script.substringAfter("deploy)\n").substringBefore("    ;;\npair)")
        val check = deploy.indexOf("ksud sepolicy check")
        val apply = deploy.indexOf("ksud sepolicy apply")
        val bind = deploy.indexOf("nsenter -t 1 -m -- mount --bind \"\$pending\" \"\$active\"")
        val start = deploy.indexOf("\"\$active/rka-supervisor.sh\" start")

        assertTrue(check >= 0 && apply > check && bind > apply && start > bind)
        assertTrue(deploy.contains("sepolicy-logcat.reject"))
        assertTrue(script.contains("cmp -s \"\$active/module.prop\" \"\$pending/module.prop\""))
    }

    @Test
    fun productionTraceCannotSelectBootStageSystemServiceOrUsbFallback() {
        assertFalse(script.contains("ksud services"))
        assertFalse(script.contains("ksud late-load"))
        assertFalse(script.contains("ksud soft-reboot"))
        assertFalse(Regex("(^|[ ;])reboot([ ;]|$)", RegexOption.MULTILINE).containsMatchIn(script))
        assertFalse(script.contains("network=usb"))
        assertTrue(script.contains("\"${'$'}network\" == direct-auto"))
    }

    @Test
    fun rollbackQuarantinesFailedPendingAndRestoresBothPriorTrees() {
        val rollback = script.substringAfter("rollback)\n").substringBefore("*) exit 2")

        assertTrue(rollback.contains("mv \"\$pending\" \"\$state/module-quarantine/\$tx.failed\""))
        assertTrue(rollback.contains("mv \"\$txn/active.tree\" \"\$active\""))
        assertTrue(rollback.contains("mv \"\$txn/pending.tree\" \"\$pending\""))
        assertTrue(rollback.contains("additive_sepolicy_may_persist=true"))
    }
}
