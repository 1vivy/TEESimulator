package org.matrix.TEESimulator.rka.identity

import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Binder

class AndroidCandidateIdentityAuthority(private val packageManager: IPackageManager) :
    CandidateIdentityAuthority {
    @Suppress("DEPRECATION")
    private val packageInfoFlags =
        PackageManager.GET_SIGNATURES.toLong() or PackageManager.GET_SIGNING_CERTIFICATES.toLong()

    @Suppress("DEPRECATION")
    override fun snapshot(uid: Int, epoch: Long): AuthoritativeIdentity {
        val user = uid / 100_000
        val names =
            packageManager.getPackagesForUid(uid)?.toList()
                ?: throw CandidateIdentityException(IdentityError.MISSING_PACKAGE)
        if (names.isEmpty() || names.toSet().size != names.size) {
            throw CandidateIdentityException(
                if (names.isEmpty()) IdentityError.MISSING_PACKAGE
                else IdentityError.DUPLICATE_PACKAGE
            )
        }
        val packages = names.map { readPackage(it, uid, user) }
        val confirmedNames = packageManager.getPackagesForUid(uid)?.toList()
        if (confirmedNames == null || confirmedNames.toSet() != names.toSet()) {
            throw CandidateIdentityException(IdentityError.PACKAGE_MANAGER_INCONSISTENT)
        }
        val confirmedPackages = confirmedNames.map { readPackage(it, uid, user) }
        if (!samePackages(packages, confirmedPackages)) {
            throw CandidateIdentityException(IdentityError.PACKAGE_MANAGER_INCONSISTENT)
        }
        return AuthoritativeIdentity(user, uid, packages)
    }

    @Suppress("DEPRECATION")
    private fun readPackage(requested: String, uid: Int, user: Int): RawPackageIdentity {
        val info = packageManager.getPackageInfo(requested, packageInfoFlags, user)
        if (info.packageName != requested || info.applicationInfo?.uid != uid) {
            throw CandidateIdentityException(IdentityError.PACKAGE_MANAGER_INCONSISTENT)
        }
        val legacy = info.signatures?.map { it.toByteArray() }.orEmpty()
        val signing = info.signingInfo
        val current = signing?.apkContentsSigners?.map { it.toByteArray() } ?: legacy
        if (legacy.isEmpty() || !sameCertificateSet(legacy, current)) {
            throw CandidateIdentityException(IdentityError.PACKAGE_MANAGER_INCONSISTENT)
        }
        val history = signing?.signingCertificateHistory?.map { it.toByteArray() } ?: current
        if (
            signing?.hasMultipleSigners() == true &&
                (signing.hasPastSigningCertificates() || history.size != current.size)
        ) {
            throw CandidateIdentityException(IdentityError.PACKAGE_MANAGER_INCONSISTENT)
        }
        return RawPackageIdentity(requested, info.longVersionCode.toULong(), current, history)
    }

    private fun sameCertificateSet(left: List<ByteArray>, right: List<ByteArray>) =
        left.size == right.size &&
            left.all { candidate -> right.any { candidate.contentEquals(it) } }

    private fun samePackages(
        left: List<RawPackageIdentity>,
        right: List<RawPackageIdentity>,
    ): Boolean {
        val a = left.sortedBy { it.name }
        val b = right.sortedBy { it.name }
        return a.size == b.size &&
            a.indices.all {
                a[it].name == b[it].name &&
                    a[it].version == b[it].version &&
                    a[it].current == b[it].current &&
                    a[it].history == b[it].history
            }
    }

    companion object {
        fun gate(packageManager: IPackageManager) =
            CandidateIdentityGate(
                Binder::getCallingUid,
                AndroidCandidateIdentityAuthority(packageManager),
            )
    }
}
