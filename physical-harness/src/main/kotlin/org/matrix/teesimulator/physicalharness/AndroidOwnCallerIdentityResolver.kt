package org.matrix.teesimulator.physicalharness

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process

class AndroidOwnCallerIdentityResolver(context: Context) {
    private val packageManager = context.packageManager
    private val canonicalizer = CallerIdentityCanonicalizer()

    fun resolve(): CanonicalCallerIdentity {
        val packageNames =
            packageManager.getPackagesForUid(Process.myUid())
                ?: throw IllegalStateException("No packages found for the application UID")
        if (packageNames.isEmpty()) {
            throw IllegalStateException("No packages found for the application UID")
        }

        return canonicalizer.canonicalize(packageNames.map(::resolvePackage))
    }

    private fun resolvePackage(packageName: String): CallerPackageIdentity {
        if (packageName.isEmpty()) {
            throw IllegalStateException("Package manager returned an empty package name")
        }
        val packageInfo =
            packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
            )
        if (packageInfo.packageName != packageName) {
            throw IllegalStateException("Package manager returned mismatched package information")
        }
        val signingInfo =
            packageInfo.signingInfo
                ?: throw IllegalStateException("Package signing information is missing")
        val signingCertificateHistory =
            signingInfo.signingCertificateHistory
                ?: throw IllegalStateException("Package signing certificate history is missing")
        if (signingCertificateHistory.isEmpty()) {
            throw IllegalStateException("Package signing certificate history is empty")
        }

        return CallerPackageIdentity(
            packageName = packageInfo.packageName,
            longVersionCode = packageInfo.longVersionCode,
            signingCertificateHistory = signingCertificateHistory.map { it.toByteArray() },
        )
    }
}
