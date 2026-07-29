package org.matrix.teesimulator.physicalharness

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import org.matrix.teesimulator.twophone.BoundedWireFrameIo
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.WireTransportFramingException

class BoundedWireFrameIoTest {
    @Test
    fun acceptsZeroAndMaximumBodiesAndReturnsDefensiveFrames() {
        val zero = frame(ByteArray(0))
        assertContentEquals(zero, BoundedWireFrameIo.read(ByteArrayInputStream(zero)))

        val maximum = frame(ByteArray(NormalizedWireCodec.MAX_FRAME_BYTES - 4) { 7 })
        val decoded = BoundedWireFrameIo.read(ZeroThenShortInputStream(maximum))!!
        assertContentEquals(maximum, decoded)
        assertNotSame(maximum, decoded)
    }

    @Test
    fun rejectsInvalidLengthsBeforeBodyAllocation() {
        assertFailsWith<WireTransportFramingException.InvalidLength> {
            BoundedWireFrameIo.read(ByteArrayInputStream(ByteBuffer.allocate(4).putInt(-1).array()))
        }
        assertFailsWith<WireTransportFramingException.Oversized> {
            BoundedWireFrameIo.read(
                ByteArrayInputStream(
                    ByteBuffer.allocate(4).putInt(NormalizedWireCodec.MAX_FRAME_BYTES - 3).array()
                )
            )
        }
    }

    @Test
    fun distinguishesCleanEofPartialPrefixAndPartialBody() {
        assertNull(BoundedWireFrameIo.read(ByteArrayInputStream(ByteArray(0))))
        for (size in 1..3) {
            assertFailsWith<WireTransportFramingException.Truncated> {
                BoundedWireFrameIo.read(ByteArrayInputStream(ByteArray(size)))
            }
        }
        val complete = frame(byteArrayOf(1, 2, 3, 4))
        for (size in 4 until complete.size) {
            assertFailsWith<WireTransportFramingException.Truncated> {
                BoundedWireFrameIo.read(ByteArrayInputStream(complete.copyOf(size)))
            }
        }
    }

    @Test
    fun readsConcatenatedFramesSequentially() {
        val first = frame(byteArrayOf(1, 2))
        val second = frame(byteArrayOf(3, 4, 5))
        val input = ByteArrayInputStream(first + second)

        assertContentEquals(first, BoundedWireFrameIo.read(input))
        assertContentEquals(second, BoundedWireFrameIo.read(input))
        assertNull(BoundedWireFrameIo.read(input))
    }

    @Test
    fun writeValidatesPrefixConsistencyAndCapThenFlushes() {
        val valid = frame(byteArrayOf(1, 2, 3))
        val output = TrackingOutputStream()
        BoundedWireFrameIo.write(output, valid)
        assertContentEquals(valid, output.toByteArray())
        kotlin.test.assertTrue(output.flushed)

        assertFailsWith<WireTransportFramingException.InvalidLength> {
            BoundedWireFrameIo.write(ByteArrayOutputStream(), valid.mutatingLength(2))
        }
        assertFailsWith<WireTransportFramingException.InvalidLength> {
            BoundedWireFrameIo.write(ByteArrayOutputStream(), ByteArray(3))
        }
        assertFailsWith<WireTransportFramingException.Oversized> {
            BoundedWireFrameIo.write(
                ByteArrayOutputStream(),
                ByteArray(NormalizedWireCodec.MAX_FRAME_BYTES + 1),
            )
        }
    }

    private fun frame(body: ByteArray) =
        ByteBuffer.allocate(body.size + 4).putInt(body.size).put(body).array()

    private fun ByteArray.mutatingLength(value: Int) =
        copyOf().also { ByteBuffer.wrap(it).putInt(value) }

    private class TrackingOutputStream : ByteArrayOutputStream() {
        var flushed = false

        override fun flush() {
            flushed = true
            super.flush()
        }
    }
}
