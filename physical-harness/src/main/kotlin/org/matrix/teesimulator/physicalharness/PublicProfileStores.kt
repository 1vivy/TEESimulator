package org.matrix.teesimulator.physicalharness

import android.content.Context
import java.io.File
import org.matrix.teesimulator.twophone.AtomicPublicProfileFile
import org.matrix.teesimulator.twophone.DonorPublicProfile
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.PublicProfileAtomicFileFacade
import org.matrix.teesimulator.twophone.PublicProfileCodec
import org.matrix.teesimulator.twophone.TargetPublicProfile
import org.matrix.teesimulator.twophone.TargetPublicProfileStore as SharedTargetPublicProfileStore

class DonorPublicProfileStore internal constructor(facade: PublicProfileAtomicFileFacade) {
    private val file = AtomicPublicProfileFile(facade)

    constructor(
        context: Context
    ) : this(
        AndroidPublicProfileAtomicFileFacade(
            File(context.applicationContext.noBackupFilesDir, FILE_NAME)
        )
    )

    fun install(encoded: ByteArray): DonorPublicProfile {
        val profile = PublicProfileCodec.decodeDonor(encoded)
        file.write(encoded)
        return profile
    }

    fun load(): DonorPublicProfile? = file.read()?.let(PublicProfileCodec::decodeDonor)

    companion object {
        const val FILE_NAME = "two-phone-donor-v1.bin"
    }
}

class TargetPublicProfileStore
internal constructor(
    expectedFixtureIdentity: FixturePackageIdentity,
    facade: PublicProfileAtomicFileFacade,
) {
    private val delegate = SharedTargetPublicProfileStore(expectedFixtureIdentity, facade)

    constructor(
        expectedFixtureIdentity: FixturePackageIdentity
    ) : this(
        expectedFixtureIdentity,
        AndroidPublicProfileAtomicFileFacade(File(FILE_PATH), REQUIRED_MODE),
    )

    fun install(encoded: ByteArray): TargetPublicProfile = delegate.install(encoded)

    fun load(): TargetPublicProfile? = delegate.load()

    companion object {
        const val FILE_PATH = SharedTargetPublicProfileStore.FILE_PATH
        const val REQUIRED_UID = SharedTargetPublicProfileStore.REQUIRED_UID
        const val REQUIRED_MODE = SharedTargetPublicProfileStore.REQUIRED_MODE
    }
}
