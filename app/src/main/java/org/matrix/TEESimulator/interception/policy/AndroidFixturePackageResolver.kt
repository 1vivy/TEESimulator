package org.matrix.TEESimulator.interception.policy

import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Build
import org.matrix.TEESimulator.logging.SystemLogger

class AndroidFixturePackageResolver(private val packageManager: () -> IPackageManager?) :
    FixturePackageResolver {
    override fun resolve(uid: Int, packageName: String): InstalledFixturePackage? {
        val manager = packageManager() ?: return null
        return try {
            val packages = manager.getPackagesForUid(uid) ?: return null
            if (packageName !in packages) return null

            val userId = uid / PER_USER_RANGE
            val packageInfo =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    manager.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                        userId,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    manager.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES,
                        userId,
                    )
                }
            if (packageInfo.packageName != packageName) return null

            val signatures = packageInfo.signingInfo?.signingCertificateHistory ?: return null
            if (signatures.isEmpty()) return null
            InstalledFixturePackage(
                uid = uid,
                packageName = packageInfo.packageName,
                versionCode = packageInfo.longVersionCode,
                signerDigests =
                    signatures.mapTo(mutableSetOf()) {
                        SigningCertificateDigest.sha256(it.toByteArray())
                    },
            )
        } catch (failure: Exception) {
            SystemLogger.warning("Failed to resolve approved fixture package identity", failure)
            null
        }
    }

    private companion object {
        const val PER_USER_RANGE = 100_000
    }
}
