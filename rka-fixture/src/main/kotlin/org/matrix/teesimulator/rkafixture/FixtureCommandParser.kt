package org.matrix.teesimulator.rkafixture

import java.nio.charset.StandardCharsets
import java.util.Base64
import org.matrix.teesimulator.twophone.PublicProfileCodec

class FixtureNonceReplayCache(private val maximumEntries: Int = MAXIMUM_NONCES) {
    private val seen = LinkedHashSet<String>()

    init {
        require(maximumEntries > 0)
    }

    @Synchronized
    fun consume(nonce: ByteArray) {
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
        if (!seen.add(encoded)) throw FixtureCommandError.ReplayedNonce
        if (seen.size > maximumEntries) seen.remove(seen.first())
    }

    private companion object {
        const val MAXIMUM_NONCES = 128
    }
}

class FixtureCommandParser(private val nonceReplayCache: FixtureNonceReplayCache) {
    fun parse(input: FixtureCommandInput): FixtureCommand {
        if (input.caller != FixtureCommandCaller.SHELL) {
            throw FixtureCommandError.UnauthorizedCaller
        }
        if (input.version != FixtureCommand.VERSION) throw FixtureCommandError.UnsupportedVersion
        input.extraNames.firstOrNull()?.let { throw FixtureCommandError.ForbiddenField(it) }
        val nonce = input.nonce.requireExact("nonce", FixtureNonce.BYTES)
        val activeRoles = parseMetadata(input.metadata)
        FixtureRoleProfile.parse(activeRoles)
        val command = parseCommand(input, nonce, activeRoles)
        nonceReplayCache.consume(nonce)
        return command
    }

    private fun parseCommand(
        input: FixtureCommandInput,
        nonce: ByteArray,
        activeRoles: Set<String>,
    ): FixtureCommand =
        when (input.action) {
            FixtureCommandAction.PROVISION -> {
                input.challenge.requireAbsent("challenge")
                input.profileId.requireAbsent("profileId")
                FixtureCommand.Provision(nonce, activeRoles, requireProfile(input.profile))
            }
            FixtureCommandAction.START -> {
                input.challenge.requireAbsent("challenge")
                input.profile.requireAbsent("profile")
                FixtureCommand.Start(nonce, activeRoles, requireProfileId(input.profileId))
            }
            FixtureCommandAction.STATUS -> {
                input.challenge.requireAbsent("challenge")
                input.profile.requireAbsent("profile")
                input.profileId.requireAbsent("profileId")
                FixtureCommand.Status(nonce, activeRoles)
            }
            FixtureCommandAction.ATTEST_SIGN -> {
                input.profile.requireAbsent("profile")
                input.profileId.requireAbsent("profileId")
                FixtureCommand.AttestSign(
                    nonce,
                    activeRoles,
                    input.challenge.requireExact("challenge", FixtureAttestationChallenge.BYTES),
                )
            }
            FixtureCommandAction.STOP -> {
                input.challenge.requireAbsent("challenge")
                input.profile.requireAbsent("profile")
                input.profileId.requireAbsent("profileId")
                FixtureCommand.Stop(nonce, activeRoles)
            }
            else -> throw FixtureCommandError.UnknownCommand
        }

    private fun parseMetadata(metadata: String?): Set<String> {
        val json = metadata ?: throw FixtureCommandError.InvalidMetadata
        if (json.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_METADATA_BYTES) {
            throw FixtureCommandError.OversizedField("metadata")
        }
        return when (json) {
            "{\"roles\":[]}" -> emptySet()
            "{\"roles\":[\"DONOR\"]}" -> setOf("DONOR")
            "{\"roles\":[\"TARGET\"]}" -> setOf("TARGET")
            "{\"roles\":[\"DONOR\",\"TARGET\"]}" -> setOf("DONOR", "TARGET")
            else -> throw FixtureCommandError.InvalidMetadata
        }
    }

    private fun requireProfile(profile: ByteArray?): ByteArray {
        val value = profile ?: throw FixtureCommandError.InvalidField("profile")
        if (value.isEmpty()) throw FixtureCommandError.InvalidField("profile")
        if (value.size > PublicProfileCodec.MAX_PROFILE_BYTES) {
            throw FixtureCommandError.OversizedField("profile")
        }
        return value
    }

    private fun requireProfileId(profileId: String?): String {
        val value = profileId ?: throw FixtureCommandError.InvalidField("profileId")
        if (!PROFILE_ID.matches(value)) throw FixtureCommandError.InvalidField("profileId")
        return value
    }

    private fun ByteArray?.requireExact(field: String, size: Int): ByteArray {
        val value = this ?: throw FixtureCommandError.InvalidField(field)
        if (value.size > size) throw FixtureCommandError.OversizedField(field)
        if (value.size != size) throw FixtureCommandError.InvalidField(field)
        return value
    }

    private fun Any?.requireAbsent(field: String) {
        if (this != null) throw FixtureCommandError.ForbiddenField(field)
    }

    private companion object {
        const val MAXIMUM_METADATA_BYTES = 256
        val PROFILE_ID = Regex("[A-Za-z0-9._-]{1,64}")
    }
}
