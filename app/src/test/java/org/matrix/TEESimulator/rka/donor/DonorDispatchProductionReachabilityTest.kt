package org.matrix.TEESimulator.rka.donor

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertTrue
import org.junit.Test

class DonorDispatchProductionReachabilityTest {
    @Test
    fun productionRuntimeUsesTheDonorDispatchAdapterCallsite() {
        // Given
        val runtime = source("bridge/DonorProvisioningRuntime.kt")
        val adapter = source("donor/DonorDispatchAdapter.kt")

        // When
        val runtimeCallsAdapter =
            runtime.contains("DonorDispatchAdapter.dispatch(message, donorBackend.value)")
        val adapterCallsDispatcher =
            adapter.contains("DonorBridgeDispatcher.dispatch(command, backend)")

        // Then
        assertTrue(runtimeCallsAdapter)
        assertTrue(adapterCallsDispatcher)
    }

    private fun source(relative: String): String {
        val path =
            Path.of(System.getProperty("user.dir"))
                .resolve("src/main/java/org/matrix/TEESimulator/rka")
                .resolve(relative)
        return String(Files.readAllBytes(path), StandardCharsets.UTF_8)
    }
}
