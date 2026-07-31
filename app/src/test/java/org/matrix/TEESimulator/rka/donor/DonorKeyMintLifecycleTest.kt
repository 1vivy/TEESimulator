package org.matrix.TEESimulator.rka.donor

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.journal.RkpJournalState

class DonorKeyMintLifecycleTest {
    @Test
    fun generateSignVerifyAndDelete() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture)
        val backend = DonorKeyMintBackend(device, fixture.journal)

        // When
        val generated = backend.generate(fixture.request()).success()
        val operation = backend.begin(fixture.alias).success()
        backend.updateAad(operation.handle, byteArrayOf(8)).success()
        backend.update(operation.handle, "message".toByteArray()).success()
        val signature = backend.finish(operation.handle, ByteArray(0)).success()

        // Then
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(
            KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(generated.publicSpki.copyBytes()))
        )
        verifier.update("message".toByteArray())
        assertTrue(verifier.verify(signature.signature.copyBytes()))
        assertEquals(3, generated.certificateChain.size)
        assertArrayEquals(fixture.rkpCertificate.encoded, generated.certificateChain[1].copyBytes())
        assertTrue(backend.delete(fixture.alias).success().deleted)
        assertEquals(RkpJournalState.DELETE, fixture.journal.recover()?.state)
        assertEquals(1, device.deleteCalls)
    }

    @Test
    fun everyLiveOperationMethodUsesOneSerializedEndpoint() {
        // Given
        val fixture = DonorFixture()
        val device = FakeDonorKeyMintDevice(fixture)
        val backend = DonorKeyMintBackend(device, fixture.journal)
        backend.generate(fixture.request()).success()
        val first = backend.begin(fixture.alias).success()

        // When
        backend.updateAad(first.handle, byteArrayOf(1)).success()
        backend.update(first.handle, byteArrayOf(2)).success()
        backend.abort(first.handle).success()
        val second = backend.begin(fixture.alias).success()
        backend.finish(second.handle, byteArrayOf(3)).success()

        // Then
        assertEquals(1, device.updateAadCalls)
        assertTrue(device.updateCalls >= 2)
        assertTrue(device.finishCalls >= 2)
        assertEquals(1, device.abortCalls)
    }
}

internal fun <T> DonorResult<T>.success(): T =
    (this as? DonorResult.Success)?.value ?: throw AssertionError("expected success, got $this")
