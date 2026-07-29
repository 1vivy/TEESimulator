package org.matrix.TEESimulator.interception.policy

import java.io.File
import org.matrix.teesimulator.twophone.PublicProfileCodec
import org.matrix.teesimulator.twophone.TargetPublicProfileStore

class InstalledTargetProfileApprovedFixtureSource(
    private val profileBytesLoader: () -> ByteArray? = { defaultProfileBytes() }
) : ApprovedFixtureProfileSource {
    override fun load(): ApprovedFixtureProfile? =
        runCatching {
                profileBytesLoader()?.let { encoded ->
                    val fixture = PublicProfileCodec.decodeTargetFixtureIdentity(encoded)
                    ApprovedFixtureProfile(
                        packageName = fixture.packageName,
                        versionCode = fixture.versionCode,
                        signerDigest = SigningCertificateDigest.parse(fixture.signerDigest.toHex()),
                    )
                }
            }
            .getOrNull()

    private companion object {
        fun defaultProfileBytes(): ByteArray? =
            File(TargetPublicProfileStore.FILE_PATH).takeIf(File::isFile)?.readBytes()

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
