package org.matrix.teesimulator.rkafixture

class FixtureProviderRuntime(
    private val parser: FixtureCommandParser,
    private val surface: FixtureCommandSurface,
    private val staging: FixtureRequestStaging,
) {
    fun beginUpload(nonce: String): FixtureRequestStaging.FixtureRequestUpload =
        staging.beginUpload(nonce)

    fun beginProxyUpload(nonce: String): FixtureRequestStaging.FixtureProxyUpload =
        staging.beginProxyUpload(nonce)

    fun executeResponse(nonce: String): String =
        try {
            FixtureCommandResponse.success(surface.execute(parser.parse(staging.consume(nonce))))
        } catch (failure: RuntimeException) {
            FixtureCommandResponse.failure(failure)
        }

    fun cleanup(nonce: String): Boolean = staging.cleanup(nonce)
}
