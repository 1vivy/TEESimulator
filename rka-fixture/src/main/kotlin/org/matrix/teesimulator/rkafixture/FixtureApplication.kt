package org.matrix.teesimulator.rkafixture

import android.app.Application
import java.io.File
import org.matrix.teesimulator.physicalharness.DonorStartupGates

class FixtureApplication : Application() {
    private val roleGate = FixtureRoleGate()

    val commandSurface: FixtureCommandSurface by lazy {
        val core =
            FixtureAttestationCore(
                AndroidFixtureAttestationKeyStore(),
                java.security.SecureRandom(),
            )
        FixtureCommandRuntime(
            roleGate,
            core,
            AndroidFixtureProfileInstaller(this),
            AndroidFixtureActivationDispatcher(this),
        )
    }

    val providerRuntime: FixtureProviderRuntime by lazy {
        FixtureProviderRuntime(
            FixtureCommandParser(FixtureNonceReplayCache()),
            commandSurface,
            FixtureRequestStaging(
                File(noBackupFilesDir, "fixture-command-v1"),
                System::currentTimeMillis,
            ),
        )
    }

    override fun onCreate() {
        super.onCreate()
        DonorStartupGates.install(FixtureDonorStartupGate(roleGate))
    }
}
