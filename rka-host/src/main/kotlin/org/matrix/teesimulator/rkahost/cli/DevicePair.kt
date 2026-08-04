package org.matrix.teesimulator.rkahost.cli

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.Base64

class HostCliException(message: String) : IllegalArgumentException(message)

object Hashes {
    fun sha256(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
}

class BoundSerial private constructor(val value: String) {
    companion object {
        private val grammar = Regex("[A-Za-z0-9._:-]{1,128}")

        fun parse(value: String): BoundSerial {
            if (
                !grammar.matches(value) || value.any { it == '\n' || it == '\r' || it == '\u0000' }
            ) {
                throw HostCliException("SERIAL_INVALID")
            }
            return BoundSerial(value)
        }
    }
}

data class DevicePairCandidate(
    val serial: BoundSerial,
    val profileSha256: String,
) {
    init {
        if (!profileSha256.matches(Regex("[0-9a-f]{64}"))) {
            throw HostCliException("PROFILE_SHA_INVALID")
        }
    }
}

data class DevicePairSnapshot(
    val donor: BoundSerial,
    val candidates: List<DevicePairCandidate>,
    val schemaVersion: Int,
) {
    constructor(donor: BoundSerial, candidate: BoundSerial, profileSha256: String) :
        this(donor, listOf(DevicePairCandidate(candidate, profileSha256)), 1)

    init {
        if (candidates.isEmpty()) throw HostCliException("CANDIDATE_MISSING")
        if (schemaVersion !in setOf(1, 2)) throw HostCliException("PAIR_SCHEMA_INVALID")
        val serials = candidates.map { it.serial.value }
        if (donor.value in serials || serials.distinct().size != serials.size) {
            throw HostCliException("ROLE_COLLISION")
        }
        if (schemaVersion == 1 && candidates.size != 1) {
            throw HostCliException("PAIR_SCHEMA_INVALID")
        }
    }

    val candidate: BoundSerial
        get() = candidates.single().serial

    val profileSha256: String
        get() = candidates.single().profileSha256

    fun canonical(): String =
        if (schemaVersion == 1) {
            """{"candidate_serial":"${candidate.value}","candidate_serial_sha256":"${Hashes.sha256(candidate.value.toByteArray())}","donor_serial":"${donor.value}","donor_serial_sha256":"${Hashes.sha256(donor.value.toByteArray())}","profile_sha256":"$profileSha256","schema_version":1}
"""
        } else {
            val entries =
                candidates.joinToString(",") {
                    """{"serial":"${it.serial.value}","serial_sha256":"${Hashes.sha256(it.serial.value.toByteArray())}","profile_sha256":"${it.profileSha256}"}"""
                }
            """{"candidates":[$entries],"donor_serial":"${donor.value}","donor_serial_sha256":"${Hashes.sha256(donor.value.toByteArray())}","schema_version":2}
"""
        }

    fun environment(): String =
        if (schemaVersion == 1) {
            listOf(
                    "RKA_DEVICE_PAIR_VERSION=1",
                    "RKA_DONOR_SERIAL_B64=${encode(donor.value)}",
                    "RKA_CANDIDATE_SERIAL_B64=${encode(candidate.value)}",
                    "RKA_PROFILE_SHA256=$profileSha256",
                )
                .joinToString("\n", postfix = "\n")
        } else {
            (listOf(
                        "RKA_DEVICE_PAIR_VERSION=2",
                        "RKA_DONOR_SERIAL_B64=${encode(donor.value)}",
                        "RKA_CANDIDATE_COUNT=${candidates.size}",
                    ) +
                    candidates.flatMapIndexed { index, candidate ->
                        listOf(
                            "RKA_CANDIDATE_${index}_SERIAL_B64=${encode(candidate.serial.value)}",
                            "RKA_CANDIDATE_${index}_PROFILE_SHA256=${candidate.profileSha256}",
                        )
                    })
                .joinToString("\n", postfix = "\n")
        }

    companion object {
        private val canonicalPattern =
            Regex(
                """\{"candidate_serial":"([A-Za-z0-9._:-]{1,128})","candidate_serial_sha256":"([0-9a-f]{64})","donor_serial":"([A-Za-z0-9._:-]{1,128})","donor_serial_sha256":"([0-9a-f]{64})","profile_sha256":"([0-9a-f]{64})","schema_version":1\}\n"""
            )
        private val canonicalV2Pattern =
            Regex(
                """\{"candidates":\[((?:\{"serial":"[A-Za-z0-9._:-]{1,128}","serial_sha256":"[0-9a-f]{64}","profile_sha256":"[0-9a-f]{64}"\})(?:,\{"serial":"[A-Za-z0-9._:-]{1,128}","serial_sha256":"[0-9a-f]{64}","profile_sha256":"[0-9a-f]{64}"\})*)\],"donor_serial":"([A-Za-z0-9._:-]{1,128})","donor_serial_sha256":"([0-9a-f]{64})","schema_version":2\}\n"""
            )
        private val candidateV2Pattern =
            Regex(
                """\{"serial":"([A-Za-z0-9._:-]{1,128})","serial_sha256":"([0-9a-f]{64})","profile_sha256":"([0-9a-f]{64})"\}"""
            )

        fun parse(raw: String): DevicePairSnapshot {
            canonicalV2Pattern.matchEntire(raw)?.let { return parseV2(it) }
            val match = canonicalPattern.matchEntire(raw) ?: throw HostCliException("PAIR_JSON_INVALID")
            val snapshot =
                DevicePairSnapshot(
                    BoundSerial.parse(match.groupValues[3]),
                    BoundSerial.parse(match.groupValues[1]),
                    match.groupValues[5],
                )
            if (
                match.groupValues[2] != Hashes.sha256(snapshot.candidate.value.toByteArray()) ||
                    match.groupValues[4] != Hashes.sha256(snapshot.donor.value.toByteArray())
            ) {
                throw HostCliException("PAIR_HASH_MISMATCH")
            }
            return snapshot
        }

        private fun parseV2(match: MatchResult): DevicePairSnapshot {
            val candidates =
                candidateV2Pattern.findAll(match.groupValues[1]).map {
                    val serial = BoundSerial.parse(it.groupValues[1])
                    if (it.groupValues[2] != Hashes.sha256(serial.value.toByteArray())) {
                        throw HostCliException("PAIR_HASH_MISMATCH")
                    }
                    DevicePairCandidate(serial, it.groupValues[3])
                }.toList()
            val donor = BoundSerial.parse(match.groupValues[2])
            if (match.groupValues[3] != Hashes.sha256(donor.value.toByteArray())) {
                throw HostCliException("PAIR_HASH_MISMATCH")
            }
            return DevicePairSnapshot(donor, candidates, 2)
        }

        private fun encode(value: String): String =
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.toByteArray(StandardCharsets.UTF_8))
    }
}

class DevicePairStore(private val root: Path) {
    fun bind(donor: String, candidate: String, profile: Path): DevicePairSnapshot {
        return bindSnapshot(
            DevicePairSnapshot(
                BoundSerial.parse(donor),
                BoundSerial.parse(candidate),
                profileSha256(profile),
            )
        )
    }

    fun bind(donor: String, candidates: List<Pair<String, Path>>): DevicePairSnapshot =
        bindSnapshot(
            DevicePairSnapshot(
                BoundSerial.parse(donor),
                candidates.map { DevicePairCandidate(BoundSerial.parse(it.first), profileSha256(it.second)) },
                2,
            )
        )

    private fun bindSnapshot(snapshot: DevicePairSnapshot): DevicePairSnapshot {
        prepareRoot()
        val lock = root.resolve(LOCK)
        ensurePrivateFile(lock)
        FileChannel.open(lock, StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel ->
            channel.lock().use {
                atomicWrite(JSON, snapshot.canonical().toByteArray())
                atomicWrite(ENV, snapshot.environment().toByteArray())
            }
        }
        return snapshot
    }

    private fun profileSha256(profile: Path): String =
        if (
            Files.isRegularFile(profile, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(profile)
        ) {
            Hashes.sha256(Files.readAllBytes(profile))
        } else {
            throw HostCliException("PROFILE_INVALID")
        }

    private fun prepareRoot() {
        Files.createDirectories(root)
        if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("RUNTIME_DIRECTORY_INVALID")
        }
        Files.setPosixFilePermissions(root, DIRECTORY_MODE)
    }

    private fun ensurePrivateFile(path: Path) {
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) Files.createFile(path)
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw HostCliException("PAIR_PATH_UNSAFE")
        }
        Files.setPosixFilePermissions(path, FILE_MODE)
    }

    private fun atomicWrite(name: String, bytes: ByteArray) {
        val temporary = Files.createTempFile(root, ".$name-", ".tmp")
        try {
            Files.setPosixFilePermissions(temporary, FILE_MODE)
            FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                it.write(ByteBuffer.wrap(bytes))
                it.force(true)
            }
            Files.move(
                temporary,
                root.resolve(name),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            FileChannel.open(root, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    companion object {
        const val JSON = "device-pair.json"
        const val ENV = "device-pair.env"
        const val LOCK = "device-pair.lock"
        private val DIRECTORY_MODE =
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            )
        private val FILE_MODE =
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    }
}
