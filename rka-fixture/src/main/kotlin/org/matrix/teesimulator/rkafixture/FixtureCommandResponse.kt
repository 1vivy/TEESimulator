package org.matrix.teesimulator.rkafixture

import java.nio.charset.StandardCharsets
import java.util.Base64

sealed class FixtureCommandResponseError(message: String) : IllegalArgumentException(message) {
    data object OversizedResponse :
        FixtureCommandResponseError("fixture command response is oversized")
}

object FixtureCommandResponse {
    fun success(result: FixtureCommandResult): String =
        checked(
            when (result) {
                FixtureCommandResult.Provisioned -> response("provision")
                FixtureCommandResult.Started -> response("start")
                FixtureCommandResult.Status -> response("status")
                FixtureCommandResult.Stopped -> response("stop")
                is FixtureCommandResult.AttestedSigned -> attestedSign(result.result)
            }
        )

    fun failure(failure: Throwable): String =
        checked("{\"version\":1,\"status\":\"error\",\"code\":\"${failureCode(failure)}\"}")

    private fun response(command: String) =
        "{\"version\":1,\"status\":\"ok\",\"command\":\"$command\"}"

    private fun attestedSign(result: FixtureAttestationResult): String {
        val base64 = Base64.getEncoder()
        val chain =
            result.certificateChainDer.joinToString(",") { certificate ->
                "\"${base64.encodeToString(certificate)}\""
            }
        return "{\"version\":1,\"status\":\"ok\",\"command\":\"attest-sign\",\"chain\":[$chain],\"payload\":\"${base64.encodeToString(result.payload)}\",\"signature\":\"${base64.encodeToString(result.signature)}\"}"
    }

    private fun checked(json: String): String {
        if (json.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_RESPONSE_BYTES) {
            throw FixtureCommandResponseError.OversizedResponse
        }
        return json
    }

    private fun failureCode(failure: Throwable): String =
        when (failure) {
            is FixtureCommandError -> failure.code.name
            is FixtureProviderError -> failure.code.name
            is FixtureRoleProfileError -> failure.code.name
            is FixtureCoreError.InvalidChallenge -> "INVALID_CHALLENGE"
            is FixtureCoreError.KeyStoreOperation ->
                "KEYSTORE_${failure.diagnostic.category.name}_${failure.diagnostic.numericCode}"
            is FixtureCoreError.AliasCleanup -> "ALIAS_CLEANUP"
            FixtureDonorStartupError.WrongRole -> "WRONG_ROLE"
            FixturePackageIdentityError.InvalidSigningIdentity -> "INVALID_SIGNING_IDENTITY"
            FixtureCommandResponseError.OversizedResponse -> "OVERSIZED_RESPONSE"
            else -> "INTERNAL_FAILURE"
        }

    private const val MAXIMUM_RESPONSE_BYTES = 1_048_576
}
