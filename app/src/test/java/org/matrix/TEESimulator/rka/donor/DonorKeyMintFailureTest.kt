package org.matrix.TEESimulator.rka.donor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.journal.RkpJournalState

class DonorKeyMintFailureTest {
    @Test
    fun appKeyGeneratingCrashCallsHardwareOnceWithoutRetryOrExposure() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture).apply { failGenerate = true }
        val backend = DonorKeyMintBackend(device, fixture.journal)

        // When
        val first = backend.generate(fixture.request())
        val second = backend.generate(fixture.request())

        // Then
        assertTrue(first is DonorResult.Failure)
        assertTrue(second is DonorResult.Failure)
        assertEquals(1, device.generateCalls)
        assertEquals(0, device.exposureCalls)
        assertEquals(RkpJournalState.QUARANTINED, fixture.journal.recover()?.state)
    }

    @Test
    fun wrongAaidIssuerSpkiOrCharacteristicsDeletesWithoutExposure() {
        listOf<(FakeDonorKeyMintDevice) -> Unit>(
                { it.wrongAaid = true },
                { it.wrongIssuer = true },
                { it.wrongSignature = true },
                { it.wrongSpki = true },
                { it.wrongCharacteristics = true },
            )
            .forEach { mutate ->
                // Given
                val fixture = DonorFixture()
                val device = FakeDonorKeyMintDevice(fixture).also(mutate)
                val backend = DonorKeyMintBackend(device, fixture.journal)

                // When
                val result = backend.generate(fixture.request())

                // Then
                assertTrue(result is DonorResult.Failure)
                assertEquals(1, device.generateCalls)
                assertEquals(1, device.deleteCalls)
                assertEquals(0, backend.list().size)
                assertEquals(RkpJournalState.QUARANTINED, fixture.journal.recover()?.state)
            }
    }

    @Test
    fun operationFailureDeletesAndQuarantinesWithoutSignature() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture)
        val backend = DonorKeyMintBackend(device, fixture.journal)
        backend.generate(fixture.request()).success()
        val operation = backend.begin(fixture.alias).success()
        device.failUpdate = true

        // When
        val result = backend.update(operation.handle, byteArrayOf(1))

        // Then
        assertTrue(result is DonorResult.Failure)
        assertEquals(1, device.deleteCalls)
        assertEquals(0, backend.list().size)
        assertEquals(RkpJournalState.QUARANTINED, fixture.journal.recover()?.state)
    }
}
