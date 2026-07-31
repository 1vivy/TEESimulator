package org.matrix.TEESimulator.rka.donor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.CandidateBridgeOperation
import org.matrix.TEESimulator.rka.bridge.PublicBytes
import org.matrix.TEESimulator.rka.bridge.RequestId

class DonorDispatchAdapterTest {
    @Test
    fun productionAdapterDispatchesTypedCommandToDonorBackend() {
        // Given
        val fixture = DonorFixture()
        val backend = DonorKeyMintBackend(FakeDonorKeyMintDevice(fixture), fixture.journal)
        val command =
            BridgeMessage.CandidateCommand(
                RequestId(21),
                CandidateBridgeOperation.LIST,
                PublicBytes.of(ByteArray(0), BridgeLimits.MAX_FRAME_BYTES - 5),
            )

        // When
        val response = DonorDispatchAdapter.dispatch(command, backend)

        // Then
        assertTrue(response is BridgeMessage.CandidateReply)
        val reply = response as BridgeMessage.CandidateReply
        assertEquals(CandidateBridgeOperation.LIST, reply.operation)
        assertEquals(0, reply.payload.copyBytes().single().toInt())
        response.close()
        command.close()
    }
}
