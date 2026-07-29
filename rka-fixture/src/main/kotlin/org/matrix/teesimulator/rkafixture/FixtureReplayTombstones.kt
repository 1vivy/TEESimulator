package org.matrix.teesimulator.rkafixture

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

internal class FixtureReplayTombstones(private val directory: File) {
    private val file = File(directory, "fixture-command-v1.replayed")
    private val tokens = LinkedHashSet<String>()

    init {
        if (file.length() > MAXIMUM_FILE_BYTES) {
            file.delete()
        } else if (file.exists()) {
            file.forEachLine { token ->
                if (TOKEN.matches(token) && tokens.size < MAXIMUM_TOKENS) tokens.add(token)
            }
        }
    }

    fun add(token: String) {
        tokens.add(token)
        if (tokens.size > MAXIMUM_TOKENS) tokens.remove(tokens.first())
        persist()
    }

    operator fun contains(token: String): Boolean = token in tokens

    private fun persist() {
        val temporary = File(directory, file.name + ".tmp")
        try {
            FileOutputStream(temporary).use { output ->
                tokens.forEach { token -> output.write((token + "\n").encodeToByteArray()) }
                output.fd.sync()
            }
            if (!temporary.renameTo(file)) throw FixtureProviderError.UploadInterrupted
        } catch (failure: IOException) {
            temporary.delete()
            throw FixtureProviderError.UploadInterrupted
        }
    }

    private companion object {
        const val MAXIMUM_TOKENS = 128
        const val MAXIMUM_FILE_BYTES = MAXIMUM_TOKENS * 23
        val TOKEN = Regex("[A-Za-z0-9_-]{22}")
    }
}
