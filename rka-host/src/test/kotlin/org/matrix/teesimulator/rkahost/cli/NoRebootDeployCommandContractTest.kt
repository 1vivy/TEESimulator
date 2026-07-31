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
        val pendingSnapshot = deploy.indexOf("tree_hash \"\$pending\" > \"\$txn/pending.before\"")
        val pendingPreserve = deploy.indexOf("cp -a \"\$pending\" \"\$txn/pending.tree\"")
        val stop = deploy.indexOf("\"\$active/rka-supervisor.sh\" stop")
        val unmount = deploy.indexOf("nsenter -t 1 -m -- umount \"\$active\"")
        val activeSnapshot = deploy.indexOf("tree_hash \"\$active\" > \"\$txn/active.before\"")
        val install = deploy.indexOf("ksud module install \"\$archive\"")

        assertTrue(pendingSnapshot >= 0 && pendingPreserve > pendingSnapshot)
        assertTrue(stop > pendingPreserve && unmount > stop)
        assertTrue(activeSnapshot > unmount && install > activeSnapshot)
        assertEquals(1, Regex("ksud module install").findAll(deploy).count())
    }

    @Test
    fun policyBindAndActiveViewStartAreStrictlyOrdered() {
        val deploy = script.substringAfter("deploy)\n").substringBefore("    ;;\npair)")
        val check = deploy.indexOf("ksud sepolicy check")
        val apply = deploy.indexOf("ksud sepolicy apply")
        val bind = deploy.indexOf("nsenter -t 1 -m -- mount --bind \"\$pending\" \"\$active\"")

        assertTrue(check >= 0 && apply > check && bind > apply)
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

    @Test
    fun liveBindSnapshotsPendingBeforeExposingAndSnapshottingHiddenActive() {
        val deploy = script.substringAfter("deploy)\n").substringBefore("    ;;\npair)")
        val pendingSnapshot = deploy.indexOf("cp -a \"\$pending\" \"\$txn/pending.tree\"")
        val unmount = deploy.indexOf("nsenter -t 1 -m -- umount \"\$active\"")
        val activeSnapshot = deploy.indexOf("cp -a \"\$active\" \"\$txn/active.tree\"")

        assertTrue(pendingSnapshot >= 0 && unmount > pendingSnapshot && activeSnapshot > unmount)
        assertTrue(deploy.contains("active.metadata.before"))
        assertTrue(deploy.contains("pending.metadata.before"))
    }

    @Test
    fun attemptIdentityIsUniqueAndBoundToSourceAndArchive() {
        assertTrue(script.contains("cat /proc/sys/kernel/random/uuid"))
        assertTrue(script.contains("source_sha=%s\\narchive_sha256=%s"))
        assertFalse(script.contains("transaction_id=\"\${source_sha:0:12}-\${archive_sha:0:12}\""))
    }

    @Test
    fun remoteArchiveAndSourceReceiptAreVerifiedBeforeInstall() {
        val deploy = script.substringAfter("deploy)\n").substringBefore("    ;;\npair)")
        val remoteHash = deploy.indexOf("sha256sum \"\$archive\"")
        val sourceReceipt = deploy.indexOf("source.receipt")
        val install = deploy.indexOf("ksud module install \"\$archive\"")

        assertTrue(remoteHash >= 0 && sourceReceipt > remoteHash && install > sourceReceipt)
        assertTrue(script.contains("\"\$expected_source_sha\" \"\$expected_archive_sha\""))
    }

    @Test
    fun completeDirectProfileIsPublishedBeforeRuntimeStartAndReloaded() {
        val pair = script.substringAfter("pair)\n").substringBefore("    ;;\ndirect-probe)")
        val profile = pair.indexOf("direct.conf")
        val start = pair.indexOf("\"\$active/rka-supervisor.sh\" start")

        assertTrue(profile >= 0 && start > profile)
        assertTrue(pair.contains("peer_spki_sha256"))
        assertTrue(pair.contains("transport=DIRECT"))
        assertTrue(pair.contains("direct-profile.receipt"))
        assertTrue(script.contains("\"\$active/rka-sidecar\" direct-probe"))
        assertTrue(script.contains("\"\$active/rka-sidecar\" direct-identity"))
        assertFalse(script.contains("openssl"))
    }

    @Test
    fun provenanceAndEveryRuntimeConsumerUseTheIntendedMountView() {
        val preflight = script.substringAfter("preflight)\n").substringBefore("    ;;\nnetwork)")
        val pair = script.substringAfter("pair)\n").substringBefore("    ;;\ndirect-probe)")

        assertTrue(preflight.contains("ksud.provenance"))
        assertFalse(preflight.contains("strings \"\$ksud\""))
        assertTrue(pair.contains("manager_pid"))
        assertTrue(pair.contains("webui_pid"))
        assertTrue(pair.contains("for name in broker sidecar"))
        assertTrue(pair.contains("\$state/run/pids/\$name.pid"))
        assertTrue(pair.contains("/proc/1/ns/mnt"))
        assertTrue(pair.contains("stat -c %d:%i"))
    }
}
