package org.matrix.teesimulator.rkafixture

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import org.matrix.teesimulator.twophone.PublicProfileCodec

data class FixtureProviderCaller(
    val uid: Int,
    val attributedPackage: String?,
    val uidPackages: Set<String>,
)

data class FixtureProviderAddress(
    val scheme: String?,
    val authority: String?,
    val encodedPath: String?,
    val query: String?,
    val fragment: String?,
    val userInfo: String?,
)

sealed class FixtureProviderRoute(val nonce: String) {
    class Request(nonce: String) : FixtureProviderRoute(nonce) {
        override fun equals(other: Any?): Boolean = other is Request && nonce == other.nonce

        override fun hashCode(): Int = nonce.hashCode()
    }

    class Execute(nonce: String) : FixtureProviderRoute(nonce) {
        override fun equals(other: Any?): Boolean = other is Execute && nonce == other.nonce

        override fun hashCode(): Int = nonce.hashCode()
    }
}

object FixtureProviderBoundary {
    const val AUTHORITY = "org.matrix.teesimulator.rkafixture.commands"
    private const val SHELL_PACKAGE = "com.android.shell"

    fun authorizeOpen(
        caller: FixtureProviderCaller,
        address: FixtureProviderAddress,
        mode: String,
    ): FixtureProviderRoute {
        verifyCaller(caller)
        val route = parseRoute(address)
        val expectedMode =
            when (route) {
                is FixtureProviderRoute.Request -> "w"
                is FixtureProviderRoute.Execute -> "r"
            }
        if (mode != expectedMode) throw FixtureProviderError.InvalidMode
        return route
    }

    fun authorizeDelete(
        caller: FixtureProviderCaller,
        address: FixtureProviderAddress,
    ): FixtureProviderRoute.Request {
        verifyCaller(caller)
        return parseRoute(address) as? FixtureProviderRoute.Request
            ?: throw FixtureProviderError.InvalidRoute
    }

    private fun verifyCaller(caller: FixtureProviderCaller) {
        if (caller.uid != android.os.Process.SHELL_UID) throw FixtureProviderError.UnauthorizedUid
        if (caller.attributedPackage != SHELL_PACKAGE || SHELL_PACKAGE !in caller.uidPackages) {
            throw FixtureProviderError.UnverifiedAttribution
        }
    }

    private fun parseRoute(address: FixtureProviderAddress): FixtureProviderRoute {
        if (address.userInfo != null) throw FixtureProviderError.CrossUserAddress
        if (address.scheme != "content" || address.authority != AUTHORITY) {
            throw FixtureProviderError.InvalidAuthority
        }
        if (address.query != null || address.fragment != null)
            throw FixtureProviderError.InvalidRoute
        val path = address.encodedPath ?: throw FixtureProviderError.InvalidRoute
        val match = ROUTE.matchEntire(path) ?: unsupportedOrInvalid(path)
        val nonce = match.groupValues[2]
        decodeNonce(nonce)
        return when (match.groupValues[1]) {
            "request" -> FixtureProviderRoute.Request(nonce)
            "execute" -> FixtureProviderRoute.Execute(nonce)
            else -> throw FixtureProviderError.InvalidRoute
        }
    }

    private fun unsupportedOrInvalid(path: String): Nothing {
        if (path.startsWith("/v") && path.substringAfter("/v").substringBefore('/') != "1") {
            throw FixtureProviderError.UnsupportedVersion
        }
        throw FixtureProviderError.InvalidRoute
    }

    private fun decodeNonce(nonce: String): ByteArray =
        try {
                Base64.getUrlDecoder().decode(nonce)
            } catch (failure: IllegalArgumentException) {
                throw FixtureProviderError.InvalidNonce
            }
            .also { value ->
                if (value.size != FixtureNonce.BYTES) throw FixtureProviderError.InvalidNonce
            }

    private val ROUTE = Regex("/v1/(request|execute)/([A-Za-z0-9_-]{22})")
}

object FixtureProviderRequestCodec {
    fun decode(bytes: ByteArray): FixtureCommandInput {
        if (bytes.size > PublicProfileCodec.MAX_PROFILE_BYTES) {
            throw FixtureProviderError.OversizedRequest
        }
        val text = strictUtf8(bytes)
        return decodeText(text)
    }

    private fun decodeText(text: String): FixtureCommandInput {
        attest.matchEntire(text)?.let { match ->
            return input(
                match.groupValues[1],
                FixtureCommandAction.ATTEST_SIGN,
                match.groupValues[2],
                decodeToken("challenge", match.groupValues[3]),
                null,
                null,
                match.groupValues[4],
            )
        }
        provision.matchEntire(text)?.let { match ->
            return input(
                match.groupValues[1],
                FixtureCommandAction.PROVISION,
                match.groupValues[2],
                null,
                decodeToken("profile", match.groupValues[3]),
                null,
                match.groupValues[4],
            )
        }
        start.matchEntire(text)?.let { match ->
            return input(
                match.groupValues[1],
                FixtureCommandAction.START,
                match.groupValues[2],
                null,
                null,
                match.groupValues[3],
                match.groupValues[4],
            )
        }
        short.matchEntire(text)?.let { match ->
            return input(
                match.groupValues[1],
                actionFor(match.groupValues[2]),
                match.groupValues[3],
                null,
                null,
                null,
                match.groupValues[4],
            )
        }
        throw FixtureProviderError.MalformedRequest
    }

    private fun input(
        version: String,
        action: String,
        nonce: String,
        challenge: ByteArray?,
        profile: ByteArray?,
        profileId: String?,
        metadata: String,
    ): FixtureCommandInput =
        FixtureCommandInput(
            FixtureCommandCaller.SHELL,
            version.toIntOrNull() ?: throw FixtureProviderError.MalformedRequest,
            action,
            decodeNonce(nonce),
            challenge,
            profile,
            profileId,
            metadata,
            emptySet(),
        )

    private fun actionFor(command: String): String =
        when (command) {
            "status" -> FixtureCommandAction.STATUS
            "stop" -> FixtureCommandAction.STOP
            else -> command
        }

    private fun decodeNonce(token: String): ByteArray {
        val value = decodeToken("nonce", token)
        if (value.size != FixtureNonce.BYTES) throw FixtureProviderError.InvalidNonce
        return value
    }

    private fun decodeToken(field: String, token: String): ByteArray {
        if (!TOKEN.matches(token)) throw FixtureProviderError.MalformedRequest
        return try {
            Base64.getUrlDecoder().decode(token)
        } catch (failure: IllegalArgumentException) {
            throw FixtureProviderError.MalformedRequest
        }
    }

    private fun strictUtf8(bytes: ByteArray): String =
        try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (failure: CharacterCodingException) {
            throw FixtureProviderError.MalformedRequest
        }

    private const val TOKEN_PATTERN = "[A-Za-z0-9_-]+"
    private const val METADATA =
        "(\\{\"roles\":\\[(?:\"DONOR\"|\"TARGET\"|\"DONOR\",\"TARGET\")?\\]\\})"
    private const val PREFIX = "\\{\"version\":([0-9]+),\"command\":\""
    private const val NONCE = "\",\"nonce\":\"($TOKEN_PATTERN)\""
    private const val SUFFIX = ",\"metadata\":$METADATA\\}"
    private val attest =
        Regex("${PREFIX}attest-sign${NONCE},\"challenge\":\"($TOKEN_PATTERN)\"$SUFFIX")
    private val provision =
        Regex("${PREFIX}provision${NONCE},\"profile\":\"($TOKEN_PATTERN)\"$SUFFIX")
    private val start =
        Regex("${PREFIX}start${NONCE},\"profileId\":\"([A-Za-z0-9._-]{1,64})\"$SUFFIX")
    private val short = Regex("${PREFIX}([a-z-]+)${NONCE}$SUFFIX")
    private val TOKEN = Regex("^$TOKEN_PATTERN$")
}
