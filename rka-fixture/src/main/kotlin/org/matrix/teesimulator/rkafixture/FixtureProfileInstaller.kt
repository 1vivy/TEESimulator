package org.matrix.teesimulator.rkafixture

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest
import org.matrix.teesimulator.physicalharness.DonorPublicProfileStore
import org.matrix.teesimulator.physicalharness.TargetPublicProfileStore
import org.matrix.teesimulator.twophone.FixturePackageIdentity

interface FixtureProfileInstaller {
    fun install(activation: FixtureRoleActivation, profile: ByteArray)
}

sealed class FixturePackageIdentityError(message: String) : SecurityException(message) {
    data object InvalidSigningIdentity :
        FixturePackageIdentityError("fixture package signer is invalid")
}

class AndroidFixtureProfileInstaller(context: Context) : FixtureProfileInstaller {
    private val context = context.applicationContext

    override fun install(activation: FixtureRoleActivation, profile: ByteArray) {
        when (activation.role) {
            FixtureRole.DONOR -> DonorPublicProfileStore(context).install(profile)
            FixtureRole.TARGET -> TargetPublicProfileStore(packageIdentity()).install(profile)
        }
    }

    private fun packageIdentity(): FixturePackageIdentity {
        val packageManager = context.packageManager
        val packageInfo =
            packageManager.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
            )
        val signatures = packageInfo.signingInfo?.apkContentsSigners.orEmpty()
        if (signatures.size != 1) throw FixturePackageIdentityError.InvalidSigningIdentity
        val signerDigest =
            MessageDigest.getInstance("SHA-256").digest(signatures.single().toByteArray())
        return FixturePackageIdentity.create(
            context.packageName,
            packageInfo.longVersionCode,
            signerDigest,
        )
    }
}
