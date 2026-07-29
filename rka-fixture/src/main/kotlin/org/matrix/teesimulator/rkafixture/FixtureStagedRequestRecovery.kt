package org.matrix.teesimulator.rkafixture

import java.io.File
import java.util.Base64

internal data class FixtureRecoveredRequest(
    val nonce: String,
    val file: File,
    val input: FixtureCommandInput,
    val expiresAtMillis: Long,
)

internal object FixtureStagedRequestRecovery {
    fun recover(directory: File, nowMillis: Long, ttlMillis: Long): List<FixtureRecoveredRequest> =
        directory.listFiles().orEmpty().mapNotNull { file ->
            when {
                file.name.endsWith(FIXTURE_REQUEST_UPLOAD_SUFFIX) -> discard(file)
                file.name.endsWith(FIXTURE_REQUEST_READY_SUFFIX) ->
                    recoverReady(file, nowMillis, ttlMillis)
                else -> null
            }
        }

    private fun recoverReady(
        file: File,
        nowMillis: Long,
        ttlMillis: Long,
    ): FixtureRecoveredRequest? {
        val nonce = file.name.removeSuffix(FIXTURE_REQUEST_READY_SUFFIX)
        val expiresAtMillis = file.lastModified() + ttlMillis
        if (!isCanonicalNonce(nonce) || expiresAtMillis <= nowMillis) return discard(file)
        val input =
            try {
                FixtureRequestFiles.decode(file)
            } catch (_: FixtureProviderError) {
                return discard(file)
            }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(input.nonce) != nonce) {
            return discard(file)
        }
        return FixtureRecoveredRequest(nonce, file, input, expiresAtMillis)
    }

    private fun isCanonicalNonce(nonce: String): Boolean {
        if (!NONCE.matches(nonce)) return false
        return try {
            Base64.getUrlDecoder().decode(nonce).size == FixtureNonce.BYTES
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun discard(file: File): Nothing? {
        file.delete()
        return null
    }

    private val NONCE = Regex("[A-Za-z0-9_-]{22}")
}
