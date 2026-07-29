package org.matrix.teesimulator.twophone

import java.io.InputStream

internal fun readTransportBytes(
    input: InputStream,
    target: ByteArray,
    offset: Int = 0,
    cleanEofAllowed: Boolean = false,
    truncated: () -> RuntimeException,
): Boolean {
    var position = offset
    while (position < target.size) {
        val count = input.read(target, position, target.size - position)
        when {
            count > 0 -> position += count
            count < 0 -> {
                if (cleanEofAllowed && position == offset) return false
                throw truncated()
            }
            else -> {
                val value = input.read()
                if (value < 0) {
                    if (cleanEofAllowed && position == offset) return false
                    throw truncated()
                }
                target[position++] = value.toByte()
            }
        }
    }
    return true
}
