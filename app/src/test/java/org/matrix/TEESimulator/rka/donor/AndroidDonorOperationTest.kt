package org.matrix.TEESimulator.rka.donor

import android.hardware.security.keymint.HardwareAuthToken
import android.hardware.security.keymint.IKeyMintOperation
import android.hardware.security.secureclock.TimeStampToken
import android.os.IBinder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidDonorOperationTest {
    @Test
    fun updateBuffersInputForSingleFinishCall() {
        val keyMint = RecordingKeyMintOperation()
        val operation = AndroidDonorOperation(keyMint)

        assertArrayEquals(ByteArray(0), operation.update(byteArrayOf(1, 2)))
        assertArrayEquals(ByteArray(0), operation.update(byteArrayOf(3)))
        assertArrayEquals(byteArrayOf(9), operation.finish(byteArrayOf(4, 5)))

        assertEquals(0, keyMint.updateCalls)
        assertEquals(1, keyMint.finishCalls)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5), keyMint.finishedInput)
    }

    private class RecordingKeyMintOperation : IKeyMintOperation {
        var updateCalls = 0
        var finishCalls = 0
        var finishedInput = ByteArray(0)

        override fun updateAad(
            input: ByteArray,
            authToken: HardwareAuthToken?,
            timeStampToken: TimeStampToken?,
        ) = Unit

        override fun update(
            input: ByteArray,
            authToken: HardwareAuthToken?,
            timeStampToken: TimeStampToken?,
        ): ByteArray {
            updateCalls += 1
            return ByteArray(0)
        }

        override fun finish(
            input: ByteArray,
            signature: ByteArray?,
            authToken: HardwareAuthToken?,
            timeStampToken: TimeStampToken?,
            confirmationToken: ByteArray?,
        ): ByteArray {
            finishCalls += 1
            finishedInput = input.copyOf()
            return byteArrayOf(9)
        }

        override fun abort() = Unit

        override fun asBinder(): IBinder? = null
    }
}
