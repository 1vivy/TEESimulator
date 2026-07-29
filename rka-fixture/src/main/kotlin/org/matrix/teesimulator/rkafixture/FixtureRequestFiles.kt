package org.matrix.teesimulator.rkafixture

import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream

internal const val FIXTURE_MAXIMUM_REQUEST_BYTES = 1_048_576

internal object FixtureRequestFiles {
    fun decode(file: File): FixtureCommandInput {
        if (file.length() > FIXTURE_MAXIMUM_REQUEST_BYTES) {
            throw FixtureProviderError.OversizedRequest
        }
        return FileInputStream(file).use { source ->
            FixtureProviderRequestCodec.decode(readBounded(source))
        }
    }

    fun readBounded(source: InputStream): ByteArray {
        val output = ByteArray(FIXTURE_MAXIMUM_REQUEST_BYTES)
        var total = 0
        while (true) {
            if (total == output.size) {
                if (source.read() >= 0) throw FixtureProviderError.OversizedRequest
                return output
            }
            val read = source.read(output, total, output.size - total)
            if (read < 0) return output.copyOf(total)
            total += read
        }
    }

    fun sync(output: java.io.FileOutputStream) {
        try {
            output.fd.sync()
        } catch (failure: IOException) {
            throw FixtureProviderError.UploadInterrupted
        }
    }
}
