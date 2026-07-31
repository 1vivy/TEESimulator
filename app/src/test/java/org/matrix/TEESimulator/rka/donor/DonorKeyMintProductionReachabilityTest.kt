package org.matrix.TEESimulator.rka.donor

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DonorKeyMintProductionReachabilityTest {
    @Test
    fun productionRuntimeReachesEveryDirectKeyMintLifecycleCall() {
        val adapter = source("donor/AndroidDonorKeyMintDevice.kt")
        val backend = source("donor/DonorKeyMintBackend.kt")
        val runtime = source("bridge/DonorProvisioningRuntime.kt")

        listOf(
                "service.generateKey(",
                "service.begin(",
                "service.deleteKey(",
                "operation.updateAad(",
                "operation.update(",
                "operation.finish(",
                "operation.abort(",
            )
            .forEach { call -> assertTrue("missing direct call: $call", adapter.contains(call)) }
        assertTrue(adapter.contains("attestKeyParams = emptyArray()"))
        assertTrue(backend.contains("rkpCertificate.subjectX500Principal.encoded"))
        assertTrue(backend.contains("RkpJournalState.APP_KEY_GENERATING"))
        assertTrue(runtime.contains("DonorDispatchAdapter.dispatch(message, donorBackend.value)"))
        assertFalse(adapter.contains("android.system.keystore2"))
        assertFalse(adapter.contains("IKeystoreSecurityLevel"))
    }

    private fun source(relative: String): String {
        val path =
            Path.of(System.getProperty("user.dir"))
                .resolve("src/main/java/org/matrix/TEESimulator/rka")
                .resolve(relative)
        return String(Files.readAllBytes(path), StandardCharsets.UTF_8)
    }
}
