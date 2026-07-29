package org.matrix.teesimulator.rkafixture

import android.os.Process
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FixtureProviderProtocolTest {
    @Test
    fun acceptsOnlyTheShellAttributionAndExactVersionedRoutes() {
        // Given: the shell's verified identity and a canonical request route. When: the provider
        // boundary authorizes it. Then: it selects a request upload with the validated nonce.
        val nonce = nonceToken()
        val caller =
            FixtureProviderCaller(
                Process.SHELL_UID,
                "com.android.shell",
                setOf("com.android.shell"),
            )
        val address = providerAddress("/v1/request/$nonce")

        val route = FixtureProviderBoundary.authorizeOpen(caller, address, "w")

        assertEquals(FixtureProviderRoute.Request(nonce), route)
    }

    @Test
    fun rejectsRootOtherCallersAndUntrustedAddressesBeforeRequestParsing() {
        // Given: unauthorized callers and malformed provider addresses. When: each is authorized.
        // Then: the boundary returns its distinct typed failure before a command can be decoded.
        val address = providerAddress("/v1/execute/${nonceToken()}")
        val shell =
            FixtureProviderCaller(
                Process.SHELL_UID,
                "com.android.shell",
                setOf("com.android.shell"),
            )
        val failures =
            listOf(
                assertFailsWith<FixtureProviderError.UnauthorizedUid> {
                    FixtureProviderBoundary.authorizeOpen(
                        FixtureProviderCaller(0, "com.android.shell", setOf("com.android.shell")),
                        address,
                        "r",
                    )
                },
                assertFailsWith<FixtureProviderError.UnauthorizedUid> {
                    FixtureProviderBoundary.authorizeOpen(
                        FixtureProviderCaller(10_001, "example", setOf("example")),
                        address,
                        "r",
                    )
                },
                assertFailsWith<FixtureProviderError.UnverifiedAttribution> {
                    FixtureProviderBoundary.authorizeOpen(
                        FixtureProviderCaller(
                            Process.SHELL_UID,
                            "example",
                            setOf("com.android.shell"),
                        ),
                        address,
                        "r",
                    )
                },
                assertFailsWith<FixtureProviderError.CrossUserAddress> {
                    FixtureProviderBoundary.authorizeOpen(
                        shell,
                        providerAddress("/v1/execute/${nonceToken()}", userInfo = "10"),
                        "r",
                    )
                },
                assertFailsWith<FixtureProviderError.InvalidMode> {
                    FixtureProviderBoundary.authorizeOpen(shell, address, "rw")
                },
                assertFailsWith<FixtureProviderError.InvalidRoute> {
                    FixtureProviderBoundary.authorizeOpen(
                        shell,
                        providerAddress("/v1/request/../../path"),
                        "w",
                    )
                },
            )

        assertEquals(5, failures.map { it::class }.toSet().size)
    }

    @Test
    fun decodesOnlyCanonicalUtf8JsonWithoutTruncationOrTrailingBytes() {
        // Given: a canonical status request. When: it is decoded from the staged byte stream.
        // Then: the existing parser receives the original fixed-size nonce and typed metadata.
        val request = statusRequest(nonceToken()).encodeToByteArray()

        val input = FixtureProviderRequestCodec.decode(request)

        assertContentEquals(nonceTokenBytes(), input.nonce)
        assertEquals(FixtureCommandAction.STATUS, input.action)
        assertEquals("{\"roles\":[\"TARGET\"]}", input.metadata)
        assertFailsWith<FixtureProviderError.MalformedRequest> {
            FixtureProviderRequestCodec.decode(request + byteArrayOf('\n'.code.toByte()))
        }
        assertFailsWith<FixtureProviderError.MalformedRequest> {
            FixtureProviderRequestCodec.decode(request.dropLast(1).toByteArray())
        }
    }

    @Test
    fun preservesTypedVersionUnknownCommandAndDualRoleFailuresForTheExistingParser() {
        // Given: canonical provider envelopes with invalid command semantics. When: the shared
        // parser receives each decoded request. Then: it retains its established typed failures.
        val parser = FixtureCommandParser(FixtureNonceReplayCache())

        assertFailsWith<FixtureCommandError.UnsupportedVersion> {
            parser.parse(
                FixtureProviderRequestCodec.decode(
                    statusRequest(nonceToken())
                        .replace("\"version\":1", "\"version\":2")
                        .encodeToByteArray()
                )
            )
        }
        assertFailsWith<FixtureCommandError.UnknownCommand> {
            parser.parse(
                FixtureProviderRequestCodec.decode(
                    statusRequest(nonceToken())
                        .replace("\"status\"", "\"unknown\"")
                        .encodeToByteArray()
                )
            )
        }
        assertFailsWith<FixtureRoleProfileError.RoleConflict> {
            parser.parse(
                FixtureProviderRequestCodec.decode(
                    statusRequest(nonceToken())
                        .replace("[\"TARGET\"]", "[\"DONOR\",\"TARGET\"]")
                        .encodeToByteArray()
                )
            )
        }
        assertFailsWith<FixtureProviderError.UnsupportedVersion> {
            FixtureProviderBoundary.authorizeOpen(
                FixtureProviderCaller(
                    Process.SHELL_UID,
                    "com.android.shell",
                    setOf("com.android.shell"),
                ),
                providerAddress("/v2/execute/${nonceToken()}"),
                "r",
            )
        }
        assertFailsWith<FixtureProviderError.InvalidRoute> {
            FixtureProviderBoundary.authorizeDelete(
                FixtureProviderCaller(
                    Process.SHELL_UID,
                    "com.android.shell",
                    setOf("com.android.shell"),
                ),
                providerAddress("/v1/execute/${nonceToken()}"),
            )
        }
    }

    private fun providerAddress(path: String, userInfo: String? = null) =
        FixtureProviderAddress(
            "content",
            FixtureCommandProvider.AUTHORITY,
            path,
            null,
            null,
            userInfo,
        )

    private fun statusRequest(nonce: String) =
        "{\"version\":1,\"command\":\"status\",\"nonce\":\"$nonce\",\"metadata\":{\"roles\":[\"TARGET\"]}}"

    private fun nonceToken() =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(nonceTokenBytes())

    private fun nonceTokenBytes() = ByteArray(FixtureNonce.BYTES) { (it + 1).toByte() }
}
