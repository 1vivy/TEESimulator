package org.matrix.teesimulator.rkafixture

import android.content.Context
import android.content.Intent
import java.util.ArrayList
import org.matrix.teesimulator.physicalharness.DonorService

interface FixtureCommandSurface {
    fun execute(command: FixtureCommand): FixtureCommandResult
}

interface FixtureActivationDispatcher {
    fun startDonor(profileId: String, activeRoles: Set<String>)

    fun startTarget(activation: FixtureRoleActivation)

    fun stopDonor()
}

class FixtureCommandRuntime(
    private val roleGate: FixtureRoleGate,
    private val core: FixtureCore,
    private val profileInstaller: FixtureProfileInstaller,
    private val activationDispatcher: FixtureActivationDispatcher,
) : FixtureCommandSurface {
    override fun execute(command: FixtureCommand): FixtureCommandResult =
        when (command) {
            is FixtureCommand.Provision ->
                roleGate.activate(command.activeRoles) { activation ->
                    profileInstaller.install(activation, command.profile)
                    FixtureCommandResult.Provisioned
                }
            is FixtureCommand.Start -> start(command)
            is FixtureCommand.Status -> FixtureCommandResult.Status
            is FixtureCommand.AttestSign ->
                roleGate.activate(command.activeRoles) { activation ->
                    FixtureCommandResult.AttestedSigned(
                        core.attestAndSign(activation, command.challenge)
                    )
                }
            is FixtureCommand.Stop -> {
                activationDispatcher.stopDonor()
                FixtureCommandResult.Stopped
            }
        }

    private fun start(command: FixtureCommand.Start): FixtureCommandResult {
        when (FixtureRoleProfile.parse(command.activeRoles)) {
            FixtureRole.DONOR ->
                activationDispatcher.startDonor(command.profileId, command.activeRoles)
            FixtureRole.TARGET ->
                roleGate.activate(command.activeRoles) { activation ->
                    activationDispatcher.startTarget(activation)
                }
        }
        return FixtureCommandResult.Started
    }
}

class AndroidFixtureActivationDispatcher(context: Context) : FixtureActivationDispatcher {
    private val context = context.applicationContext

    override fun startDonor(profileId: String, activeRoles: Set<String>) {
        context.startForegroundService(
            Intent(context, DonorService::class.java)
                .setAction(DonorService.ACTION_START)
                .putExtra(DonorService.EXTRA_PROFILE_ID, profileId)
                .putStringArrayListExtra(DonorService.EXTRA_ACTIVE_ROLES, ArrayList(activeRoles))
        )
    }

    override fun startTarget(activation: FixtureRoleActivation) = Unit

    override fun stopDonor() {
        context.startService(
            Intent(context, DonorService::class.java)
                .setAction(DonorService.ACTION_STOP)
                .putStringArrayListExtra(
                    DonorService.EXTRA_ACTIVE_ROLES,
                    arrayListOf(FixtureRole.DONOR.name),
                )
        )
    }
}
