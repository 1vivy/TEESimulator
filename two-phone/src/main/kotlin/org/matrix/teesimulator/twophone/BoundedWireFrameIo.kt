package org.matrix.teesimulator.twophone

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

sealed class WireTransportFramingException(message: String) : RuntimeException(message) {
    class InvalidLength : WireTransportFramingException("invalid transport frame length")

    class Oversized : WireTransportFramingException("transport frame exceeds limit")

    class Truncated : WireTransportFramingException("truncated transport frame")
}

object BoundedWireFrameIo {
    private const val PREFIX_BYTES = Int.SIZE_BYTES

    fun read(input: InputStream): ByteArray? {
        val prefix = ByteArray(PREFIX_BYTES)
        if (
            !readTransportBytes(
                input,
                prefix,
                cleanEofAllowed = true,
                truncated = { WireTransportFramingException.Truncated() },
            )
        ) {
            return null
        }
        val bodyBytes = ByteBuffer.wrap(prefix).int
        validateBodyLength(bodyBytes)
        val frame = ByteArray(PREFIX_BYTES + bodyBytes)
        prefix.copyInto(frame)
        readTransportBytes(
            input,
            frame,
            offset = PREFIX_BYTES,
            truncated = { WireTransportFramingException.Truncated() },
        )
        return frame
    }

    fun write(output: OutputStream, frame: ByteArray) {
        if (frame.size > NormalizedWireCodec.MAX_FRAME_BYTES) {
            throw WireTransportFramingException.Oversized()
        }
        if (frame.size < PREFIX_BYTES) throw WireTransportFramingException.InvalidLength()
        val bodyBytes = ByteBuffer.wrap(frame, 0, PREFIX_BYTES).int
        validateBodyLength(bodyBytes)
        if (bodyBytes != frame.size - PREFIX_BYTES) {
            throw WireTransportFramingException.InvalidLength()
        }
        output.write(frame)
        output.flush()
    }

    private fun validateBodyLength(bodyBytes: Int) {
        if (bodyBytes < 0) throw WireTransportFramingException.InvalidLength()
        if (bodyBytes > NormalizedWireCodec.MAX_FRAME_BYTES - PREFIX_BYTES) {
            throw WireTransportFramingException.Oversized()
        }
    }
}
