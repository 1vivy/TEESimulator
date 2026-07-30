package org.matrix.TEESimulator.rka.identity

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.CertificateFactory

enum class IdentityError {
    INVALID_UID,
    INVALID_PACKAGE_NAME,
    MISSING_PACKAGE,
    DUPLICATE_PACKAGE,
    MISSING_CURRENT_SIGNER,
    DUPLICATE_CURRENT_SIGNER,
    DUPLICATE_LINEAGE_SIGNER,
    INCONSISTENT_SHARED_UID_SIGNERS,
    MALFORMED_SIGNER,
    LIMIT_EXCEEDED,
    PACKAGE_MANAGER_INCONSISTENT,
    IDENTITY_DRIFT,
    STALE_ADMISSION,
}

class CandidateIdentityException(val error: IdentityError) :
    IllegalArgumentException("candidate identity rejected: $error")

internal class Bytes(bytes: ByteArray) {
    private val value = bytes.clone()

    fun copy() = value.clone()

    fun same(other: Bytes) = value.contentEquals(other.value)

    override fun equals(other: Any?) = other is Bytes && same(other)

    override fun hashCode() = value.contentHashCode()

    override fun toString() = "<redacted:${value.size} bytes>"
}

class RawPackageIdentity(
    val name: String,
    val version: ULong,
    currentSigners: List<ByteArray>,
    signingHistory: List<ByteArray> = currentSigners,
) {
    internal val current = currentSigners.map(::Bytes)
    internal val history = signingHistory.map(::Bytes)

    override fun toString() =
        "RawPackageIdentity(name=<redacted>, version=$version, signers=${current.size})"
}

data class AuthoritativeIdentity(
    val androidUser: Int,
    val uid: Int,
    val packages: List<RawPackageIdentity>,
)

class CanonicalPackage
internal constructor(val name: String, val version: ULong, signers: List<Bytes>) {
    private val signers = signers.toList()

    fun currentSigners() = signers.map(Bytes::copy)

    internal fun sameIdentity(other: CanonicalPackage) =
        name == other.name &&
            version == other.version &&
            signers.size == other.signers.size &&
            signers.indices.all { signers[it].same(other.signers[it]) }

    override fun toString() =
        "CanonicalPackage(name=<redacted>, version=$version, signers=${signers.size})"
}

class CandidateIdentitySnapshot
internal constructor(
    val androidUser: Int,
    val uid: Int,
    val epoch: Long,
    packages: List<CanonicalPackage>,
    aaid: ByteArray,
    aaidHash: ByteArray,
    lineageHash: ByteArray,
    identityHash: ByteArray,
) {
    val packages = packages.toList()
    private val aaid = Bytes(aaid)
    private val aaidDigest = Bytes(aaidHash)
    private val lineageDigest = Bytes(lineageHash)
    private val identityDigest = Bytes(identityHash)

    fun aaidDer() = aaid.copy()

    fun aaidHash() = aaidDigest.copy()

    fun policyLineageHash() = lineageDigest.copy()

    fun identityHash() = identityDigest.copy()

    fun canonicalCbor() =
        Cbor.map(
            0uL to Cbor.uint(androidUser.toULong()),
            1uL to Cbor.uint(uid.toULong()),
            2uL to
                Cbor.array(
                    *packages
                        .map {
                            Cbor.array(
                                Cbor.text(it.name),
                                Cbor.uint(it.version),
                                Cbor.array(*it.currentSigners().map(Cbor::bytes).toTypedArray()),
                            )
                        }
                        .toTypedArray()
                ),
            3uL to Cbor.bytes(aaid.copy()),
            4uL to Cbor.bytes(identityDigest.copy()),
            5uL to Cbor.bytes(lineageDigest.copy()),
        )

    internal fun sameIdentity(other: CandidateIdentitySnapshot) =
        androidUser == other.androidUser &&
            uid == other.uid &&
            packages.size == other.packages.size &&
            packages.indices.all { packages[it].sameIdentity(other.packages[it]) } &&
            identityDigest.same(other.identityDigest) &&
            aaid.same(other.aaid) &&
            aaidDigest.same(other.aaidDigest) &&
            lineageDigest.same(other.lineageDigest)

    override fun toString() =
        "CandidateIdentitySnapshot(user=$androidUser, uid=<redacted>, epoch=$epoch, identityHash=<redacted>)"
}

object CandidateIdentityCanonicalizer {
    private val identityDomain =
        "TEESIM-RKA-V2/IDENTITY\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val aaidDomain = "TEESIM-RKA-V2/AAID\u0000".toByteArray(StandardCharsets.US_ASCII)

    fun canonicalize(
        androidUser: Int,
        uid: Int,
        packages: List<RawPackageIdentity>,
        epoch: Long,
    ): CandidateIdentitySnapshot {
        reject(
            uid < 0 || androidUser < 0 || uid / 100_000 != androidUser,
            IdentityError.INVALID_UID,
        )
        reject(packages.isEmpty(), IdentityError.MISSING_PACKAGE)
        reject(packages.size > 16, IdentityError.LIMIT_EXCEEDED)
        val checked = packages.map(::checkPackage).sortedWith { a, b -> compare(a.first, b.first) }
        reject(
            checked.zipWithNext().any { (a, b) -> a.first.contentEquals(b.first) },
            IdentityError.DUPLICATE_PACKAGE,
        )
        val signerSet = checked.first().second.current
        reject(
            checked.any { (_, p) -> !sameSet(signerSet, p.current) },
            IdentityError.INCONSISTENT_SHARED_UID_SIGNERS,
        )
        val canonical = checked.map { (_, p) -> CanonicalPackage(p.name, p.version, p.current) }
        val aaid = Der.aaid(checked.map { it.second }, signerSet)
        reject(aaid.size > 128 * 1024, IdentityError.LIMIT_EXCEEDED)
        val lineageEntries =
            checked.map { (_, p) ->
                Cbor.array(
                    Cbor.text(p.name),
                    Cbor.array(
                        *p.history
                            .map { Cbor.bytes(hash(identityDomain, it.copy())) }
                            .toTypedArray()
                    ),
                )
            }
        val lineage =
            hash(
                identityDomain,
                Cbor.map(
                    0uL to Cbor.text("policy-lineage"),
                    1uL to Cbor.array(*lineageEntries.toTypedArray()),
                ),
            )
        val withoutHash =
            Cbor.map(
                0uL to Cbor.uint(androidUser.toULong()),
                1uL to Cbor.uint(uid.toULong()),
                2uL to
                    Cbor.array(
                        *canonical
                            .map {
                                Cbor.array(
                                    Cbor.text(it.name),
                                    Cbor.uint(it.version),
                                    Cbor.array(*it.currentSigners().map(Cbor::bytes).toTypedArray()),
                                )
                            }
                            .toTypedArray()
                    ),
                3uL to Cbor.bytes(aaid),
                5uL to Cbor.bytes(lineage),
            )
        return CandidateIdentitySnapshot(
            androidUser,
            uid,
            epoch,
            canonical,
            aaid,
            hash(aaidDomain, aaid),
            lineage,
            hash(identityDomain, withoutHash),
        )
    }

    private fun checkPackage(pkg: RawPackageIdentity): Pair<ByteArray, RawPackageIdentity> {
        reject(
            pkg.name.isEmpty() || pkg.name.any(Char::isSurrogate),
            IdentityError.INVALID_PACKAGE_NAME,
        )
        val name = pkg.name.toByteArray(StandardCharsets.UTF_8)
        reject(name.size > 255, IdentityError.LIMIT_EXCEEDED)
        reject(pkg.current.isEmpty(), IdentityError.MISSING_CURRENT_SIGNER)
        reject(pkg.current.size > 8 || pkg.history.size > 16, IdentityError.LIMIT_EXCEEDED)
        reject(
            (pkg.current + pkg.history).any { it.copy().size !in 1..8192 },
            IdentityError.LIMIT_EXCEEDED,
        )
        reject(
            (pkg.current + pkg.history).any { !validCertificate(it.copy()) },
            IdentityError.MALFORMED_SIGNER,
        )
        val current = pkg.current.sortedWith { a, b -> compare(a.copy(), b.copy()) }
        reject(
            current.zipWithNext().any { (a, b) -> a.same(b) },
            IdentityError.DUPLICATE_CURRENT_SIGNER,
        )
        reject(pkg.history.toSet().size != pkg.history.size, IdentityError.DUPLICATE_LINEAGE_SIGNER)
        return name to
            RawPackageIdentity(
                pkg.name,
                pkg.version,
                current.map(Bytes::copy),
                pkg.history.map(Bytes::copy),
            )
    }

    private fun sameSet(a: List<Bytes>, b: List<Bytes>) =
        a.size == b.size && a.indices.all { a[it].same(b[it]) }

    private fun validCertificate(der: ByteArray) =
        runCatching {
                val input = der.inputStream()
                val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input)
                input.available() == 0 && certificate.encoded.contentEquals(der)
            }
            .getOrDefault(false)

    private fun reject(condition: Boolean, error: IdentityError) {
        if (condition) throw CandidateIdentityException(error)
    }

    internal fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val difference = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (difference != 0) return difference
        }
        return a.size - b.size
    }

    private fun hash(domain: ByteArray, value: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(domain + value)
}
