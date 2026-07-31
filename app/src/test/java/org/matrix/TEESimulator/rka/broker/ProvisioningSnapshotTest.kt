package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertEquals
import org.junit.Test

class ProvisioningSnapshotTest {
    @Test
    fun captureReadsEveryObservationExactlyOnce() {
        val source = RecordingObservationSource()

        val snapshot = ProvisioningSnapshot.capture(source)

        assertEquals(
            listOf(
                "activeBaseUrl",
                "rolloutId",
                "buildFingerprint",
                "rkpdVersion",
                "apexVersion",
                "packageVersion",
                "provisioningConfig",
                "failureWindowStartMillis",
                "failureCount",
                "dataBudgetWindowStartMillis",
                "dataBudgetBytes",
                "defaultTeeIrpcIdentity",
            ),
            source.reads,
        )
        assertEquals("https://rkp.example", snapshot.activeBaseUrl)
        assertEquals(42, snapshot.rolloutId)
        assertEquals("brand/device/product:16/BP2A/42:user/release-keys", snapshot.buildFingerprint)
        assertEquals("rkpd-16", snapshot.rkpdVersion)
        assertEquals("com.android.rkpd.apex@16", snapshot.apexVersion)
        assertEquals("com.android.rkpdapp@42", snapshot.packageVersion)
        assertEquals("enabled", snapshot.provisioningConfig)
        assertEquals(100L, snapshot.failureWindowStartMillis)
        assertEquals(2, snapshot.failureCount)
        assertEquals(200L, snapshot.dataBudgetWindowStartMillis)
        assertEquals(4096L, snapshot.dataBudgetBytes)
        assertEquals(
            "android.hardware.security.keymint.IRemotelyProvisionedComponent/default",
            snapshot.defaultTeeIrpcIdentity,
        )
    }
}

internal class RecordingObservationSource : ProvisioningObservationSource {
    val reads = mutableListOf<String>()

    private fun <T> read(name: String, value: T): T {
        reads += name
        return value
    }

    override val activeBaseUrl
        get() = read("activeBaseUrl", "https://rkp.example")

    override val rolloutId
        get() = read("rolloutId", 42)

    override val buildFingerprint
        get() = read("buildFingerprint", "brand/device/product:16/BP2A/42:user/release-keys")

    override val rkpdVersion
        get() = read("rkpdVersion", "rkpd-16")

    override val apexVersion
        get() = read("apexVersion", "com.android.rkpd.apex@16")

    override val packageVersion
        get() = read("packageVersion", "com.android.rkpdapp@42")

    override val provisioningConfig
        get() = read("provisioningConfig", "enabled")

    override val failureWindowStartMillis
        get() = read("failureWindowStartMillis", 100L)

    override val failureCount
        get() = read("failureCount", 2)

    override val dataBudgetWindowStartMillis
        get() = read("dataBudgetWindowStartMillis", 200L)

    override val dataBudgetBytes
        get() = read("dataBudgetBytes", 4096L)

    override val defaultTeeIrpcIdentity
        get() =
            read(
                "defaultTeeIrpcIdentity",
                "android.hardware.security.keymint.IRemotelyProvisionedComponent/default",
            )
}
