package org.matrix.teesimulator.rkafixture

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FixtureProviderRuntimeTest {
    @Test
    fun executesAStagedRequestOnceThroughTheSharedRoleGatedSurface() {
        // Given: a staged attest-sign request and the shared runtime. When: the provider executes
        // it. Then: raw canonical JSON reaches EOF after exactly one role-gated core operation.
        val directory = Files.createTempDirectory("fixture-provider-runtime").toFile()
        try {
            val activationCalls = AtomicInteger()
            val core = RecordingCore()
            val surface =
                fixtureSurface(FixtureRoleGate { activationCalls.incrementAndGet() }, core)
            val provider =
                FixtureProviderRuntime(
                    FixtureCommandParser(FixtureNonceReplayCache()),
                    surface,
                    FixtureRequestStaging(directory, { 0L }),
                )
            val nonce = nonce()
            provider.beginUpload(nonce).writeFrom(attestRequest(nonce).byteInputStream())

            val response = provider.executeResponse(nonce)

            assertEquals(1, activationCalls.get())
            assertEquals(1, core.calls)
            assertFalse(response.endsWith("\n"))
            assertTrue(response.startsWith("{\"version\":1,\"status\":\"ok\""))
            assertEquals(
                "{\"version\":1,\"status\":\"error\",\"code\":\"DUPLICATE_EXECUTE\"}",
                provider.executeResponse(nonce),
            )
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun fixtureSurface(roleGate: FixtureRoleGate, core: FixtureCore) =
        FixtureCommandRuntime(roleGate, core, InertProfileInstaller, InertActivationDispatcher)

    private fun attestRequest(nonce: String): String =
        "{\"version\":1,\"command\":\"attest-sign\",\"nonce\":\"$nonce\",\"challenge\":\"${Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))}\",\"metadata\":{\"roles\":[\"TARGET\"]}}"

    private fun nonce(): String =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(ByteArray(FixtureNonce.BYTES) { it.toByte() })

    private object InertProfileInstaller : FixtureProfileInstaller {
        override fun install(activation: FixtureRoleActivation, profile: ByteArray) = Unit
    }

    private object InertActivationDispatcher : FixtureActivationDispatcher {
        override fun startDonor(profileId: String, activeRoles: Set<String>) = Unit

        override fun startTarget(activation: FixtureRoleActivation) = Unit

        override fun stopDonor() = Unit
    }

    private class RecordingCore : FixtureCore {
        var calls = 0

        override fun attestAndSign(
            activation: FixtureRoleActivation,
            challenge: ByteArray,
        ): FixtureAttestationResult {
            calls += 1
            return FixtureAttestationResult(emptyList(), ByteArray(32), ByteArray(64))
        }
    }
}
