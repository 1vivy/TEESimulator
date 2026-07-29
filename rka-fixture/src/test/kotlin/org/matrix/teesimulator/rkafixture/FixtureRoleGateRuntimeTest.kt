package org.matrix.teesimulator.rkafixture

import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class FixtureRoleGateRuntimeTest {
    @Test
    fun validSingleRoleActivatesExactlyOnceBeforeTheSharedCoreCreatesAKey() {
        // Given: a valid target command and an activation callback. When: the shared surface runs
        // the command. Then: validation fires once before the core receives the key operation.
        val activationCalls = AtomicInteger()
        val core = RecordingCore()
        val runtime = runtime(FixtureRoleGate { activationCalls.incrementAndGet() }, core)

        runtime.execute(attestSignCommand(setOf("TARGET")))

        assertEquals(1, activationCalls.get())
        assertEquals(1, core.attestCalls)
    }

    @Test
    fun validAttestSignCommandParsesAndSucceedsThroughTheSharedSurface() {
        // Given: a valid shell command. When: it crosses the parser and shared surface. Then: the
        // command succeeds instead of being rejected by a fail-closed-only implementation.
        val core = RecordingCore()
        val command =
            FixtureCommandParser(FixtureNonceReplayCache())
                .parse(
                    FixtureCommandInput(
                        FixtureCommandCaller.SHELL,
                        FixtureCommand.VERSION,
                        FixtureCommandAction.ATTEST_SIGN,
                        nonce(),
                        ByteArray(FixtureAttestationChallenge.BYTES),
                        null,
                        null,
                        "{\"roles\":[\"TARGET\"]}",
                        emptySet(),
                    )
                )

        assertIs<FixtureCommandResult.AttestedSigned>(
            runtime(FixtureRoleGate(), core).execute(command)
        )
        assertEquals(1, core.attestCalls)
    }

    @Test
    fun bypassingTheRoleGateCannotCreateAKeyOrBindTheDonorListener() {
        // Given: dual roles and a listener bind callback. When: either activation path is invoked.
        // Then: both reject before the key operation or listener bind can occur.
        val core = RecordingCore()
        val runtime = runtime(FixtureRoleGate(), core)
        val listenerBinds = AtomicInteger()
        val donorGate = FixtureDonorStartupGate(FixtureRoleGate())

        assertFailsWith<FixtureRoleProfileError.RoleConflict> {
            runtime.execute(attestSignCommand(setOf("DONOR", "TARGET")))
        }
        assertFailsWith<FixtureRoleProfileError.RoleConflict> {
            donorGate.runWhenAuthorized(setOf("DONOR", "TARGET")) {
                listenerBinds.incrementAndGet()
            }
        }

        assertEquals(0, core.attestCalls)
        assertEquals(0, listenerBinds.get())
    }

    @Test
    fun activityDelegateUsesTheSameCommandSurface() {
        // Given: a command surface shared with the receiver. When: the Activity delegate submits a
        // command. Then: the surface receives that exact command once.
        val surface = RecordingSurface()
        val command = FixtureCommand.Status(nonce(), setOf("TARGET"))

        assertEquals(FixtureCommandResult.Status, FixtureActivityDelegate(surface).submit(command))
        assertEquals(listOf<FixtureCommand>(command), surface.commands)
    }

    private fun runtime(roleGate: FixtureRoleGate, core: FixtureCore) =
        FixtureCommandRuntime(roleGate, core, InertProfileInstaller, InertActivationDispatcher)

    private fun attestSignCommand(roles: Set<String>) =
        FixtureCommand.AttestSign(
            nonce(),
            roles,
            ByteArray(FixtureAttestationChallenge.BYTES) { it.toByte() },
        )

    private fun nonce() = ByteArray(FixtureNonce.BYTES) { (it + 1).toByte() }

    private object InertProfileInstaller : FixtureProfileInstaller {
        override fun install(activation: FixtureRoleActivation, profile: ByteArray) = Unit
    }

    private object InertActivationDispatcher : FixtureActivationDispatcher {
        override fun startDonor(profileId: String, activeRoles: Set<String>) = Unit

        override fun startTarget(activation: FixtureRoleActivation) = Unit

        override fun stopDonor() = Unit
    }

    private class RecordingCore : FixtureCore {
        var attestCalls = 0

        override fun attestAndSign(
            activation: FixtureRoleActivation,
            challenge: ByteArray,
        ): FixtureAttestationResult {
            attestCalls += 1
            return FixtureAttestationResult(emptyList(), ByteArray(0), ByteArray(0))
        }
    }

    private class RecordingSurface : FixtureCommandSurface {
        val commands = mutableListOf<FixtureCommand>()

        override fun execute(command: FixtureCommand): FixtureCommandResult {
            commands += command
            return FixtureCommandResult.Status
        }
    }
}
