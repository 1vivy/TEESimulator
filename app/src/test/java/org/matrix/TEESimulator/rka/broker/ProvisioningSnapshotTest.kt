package org.matrix.TEESimulator.rka.broker

import java.lang.reflect.Proxy
import org.junit.Assert.assertEquals
import org.junit.Test

class ProvisioningSnapshotTest {
    @Test
    fun captureReadsEveryObservationExactlyOnce() {
        val calls = mutableListOf<String>()
        val observations =
            mapOf(
                "getActiveBaseUrl" to "https://rkp.example",
                "getRolloutId" to 42,
                "getBuildFingerprint" to "brand/device/product:16/BP2A/42:user/release-keys",
                "getRkpdVersion" to "rkpd-16",
                "getApexVersion" to "com.android.rkpd.apex@16",
                "getPackageVersion" to "com.android.rkpdapp@42",
                "getProvisioningConfig" to "enabled",
                "getFailureWindowStartMillis" to 100L,
                "getFailureCount" to 2,
                "getDataBudgetWindowStartMillis" to 200L,
                "getDataBudgetBytes" to 4096L,
                "getDefaultTeeIrpcIdentity" to
                    "android.hardware.security.keymint.IRemotelyProvisionedComponent/default",
            )
        val source =
            Proxy.newProxyInstance(
                javaClass.classLoader,
                arrayOf(ProvisioningObservationSource::class.java),
            ) { _, method, _ ->
                calls += method.name
                observations[method.name]
                    ?: error("capture attempted non-observation call ${method.name}")
            } as ProvisioningObservationSource
        assertEquals(
            observations.keys.sorted(),
            ProvisioningObservationSource::class.java.declaredMethods.map { it.name }.sorted(),
        )

        val snapshot = ProvisioningSnapshot.capture(source)

        assertEquals(
            listOf(
                "getActiveBaseUrl",
                "getRolloutId",
                "getBuildFingerprint",
                "getRkpdVersion",
                "getApexVersion",
                "getPackageVersion",
                "getProvisioningConfig",
                "getFailureWindowStartMillis",
                "getFailureCount",
                "getDataBudgetWindowStartMillis",
                "getDataBudgetBytes",
                "getDefaultTeeIrpcIdentity",
            ),
            calls,
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
