package org.matrix.teesimulator.rkafixture

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class FixtureCommandParserTest {
    @Test
    fun rejectsEachForbiddenCommandInputWithItsOwnTypedFailure() {
        // Given: a parser and malformed command inputs. When: each input is parsed. Then: each
        // boundary failure retains its specific type.
        val parser = FixtureCommandParser(FixtureNonceReplayCache())
        val failures =
            listOf(
                assertFailsWith<FixtureCommandError.UnauthorizedCaller> {
                    parser.parse(commandInput(caller = FixtureCommandCaller.OTHER))
                },
                assertFailsWith<FixtureCommandError.UnknownCommand> {
                    parser.parse(commandInput(action = "unknown"))
                },
                assertFailsWith<FixtureCommandError.OversizedField> {
                    parser.parse(commandInput(challenge = ByteArray(33)))
                },
                assertFailsWith<FixtureCommandError.ForbiddenField> {
                    parser.parse(commandInput(extraNames = setOf("path")))
                },
                assertFailsWith<FixtureRoleProfileError.RoleConflict> {
                    parser.parse(commandInput(metadata = "{\"roles\":[\"DONOR\",\"TARGET\"]}"))
                },
            )

        assertEquals(5, failures.map { it::class }.toSet().size)
    }

    @Test
    fun rejectsAReplayedNonceAfterAValidCommand() {
        // Given: one valid request. When: the exact nonce is submitted twice. Then: the second
        // request is typed as a replay.
        val parser = FixtureCommandParser(FixtureNonceReplayCache())
        val request = commandInput()

        assertIs<FixtureCommand.AttestSign>(parser.parse(request))
        assertFailsWith<FixtureCommandError.ReplayedNonce> { parser.parse(request) }
    }

    private fun commandInput(
        caller: FixtureCommandCaller = FixtureCommandCaller.SHELL,
        action: String = FixtureCommandAction.ATTEST_SIGN,
        challenge: ByteArray = ByteArray(FixtureAttestationChallenge.BYTES) { it.toByte() },
        metadata: String = "{\"roles\":[\"TARGET\"]}",
        extraNames: Set<String> = emptySet(),
    ) =
        FixtureCommandInput(
            caller,
            FixtureCommand.VERSION,
            action,
            ByteArray(FixtureNonce.BYTES) { (it + 1).toByte() },
            challenge,
            null,
            null,
            metadata,
            extraNames,
        )
}
