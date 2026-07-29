package org.matrix.teesimulator.twophone

class TargetPublicProfileStore(
    private val expectedFixtureIdentity: FixturePackageIdentity,
    facade: PublicProfileAtomicFileFacade,
) {
    private val file = AtomicPublicProfileFile(facade)

    fun install(encoded: ByteArray): TargetPublicProfile {
        val profile = PublicProfileCodec.decodeTarget(encoded, expectedFixtureIdentity)
        file.write(encoded)
        return profile
    }

    fun load(): TargetPublicProfile? =
        file.read()?.let { PublicProfileCodec.decodeTarget(it, expectedFixtureIdentity) }

    companion object {
        const val FILE_PATH = "/data/adb/tricky_store/two-phone-target-v1.bin"
        const val REQUIRED_UID = 0
        const val REQUIRED_MODE = 0x180
    }
}
