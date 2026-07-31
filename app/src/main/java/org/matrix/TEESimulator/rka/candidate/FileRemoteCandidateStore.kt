package org.matrix.TEESimulator.rka.candidate

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

class FileRemoteCandidateStore(private val root: Path) : RemoteCandidateStore {
    init {
        Files.createDirectories(root)
        require(!Files.isSymbolicLink(root))
        runCatching {
            Files.setPosixFilePermissions(
                root,
                setOf(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                ),
            )
        }
    }

    @Synchronized
    override fun all(): List<CandidateKeyRecord> =
        Files.newDirectoryStream(root, "*.rka").use { files ->
            files.map { path ->
                require(!Files.isSymbolicLink(path))
                CandidateRecordCodec.decode(Files.readAllBytes(path))
            }
        }

    @Synchronized
    override fun find(id: CandidateKeyId): CandidateKeyRecord? {
        val path = path(id)
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return null
        require(!Files.isSymbolicLink(path))
        return CandidateRecordCodec.decode(Files.readAllBytes(path))
    }

    @Synchronized
    override fun replace(record: CandidateKeyRecord) {
        replaceAtomically(path(record.id), CandidateRecordCodec.encode(record))
    }

    @Synchronized
    override fun operationStates(): List<CandidateOperationRecord> =
        Files.newDirectoryStream(root, "*.operation").use { files ->
            files.map { path ->
                require(!Files.isSymbolicLink(path))
                CandidateOperationCodec.decode(Files.readAllBytes(path))
            }
        }

    @Synchronized
    override fun replaceOperation(record: CandidateOperationRecord) {
        val name = record.handle.copyBytes().joinToString("") { "%02x".format(it) }
        replaceAtomically(root.resolve("$name.operation"), CandidateOperationCodec.encode(record))
    }

    private fun replaceAtomically(target: Path, encoded: ByteArray) {
        val temporary = Files.createTempFile(root, ".candidate-", ".tmp")
        try {
            FileOutputStream(temporary.toFile()).use {
                it.write(encoded)
                it.fd.sync()
            }
            Files.move(
                temporary,
                target,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            FileChannel.open(root, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun path(id: CandidateKeyId): Path {
        val name =
            MessageDigest.getInstance("SHA-256")
                .digest("${id.uid}:${id.namespace}:${id.alias}".toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
        return root.resolve("$name.rka")
    }
}

private object CandidateRecordCodec {
    private const val MAGIC = 0x524b4331
    private const val VERSION = 2

    fun encode(record: CandidateKeyRecord): ByteArray {
        val body =
            ByteArrayOutputStream()
                .also { bytes ->
                    DataOutputStream(bytes).use { out ->
                        out.writeInt(MAGIC)
                        out.writeInt(VERSION)
                        out.writeInt(record.id.uid)
                        out.writeLong(record.id.namespace)
                        out.writeUTF(record.id.alias)
                        out.write(record.identityHash.copyBytes())
                        out.writeLong(record.donorEpoch)
                        out.writeLong(record.profileEpoch)
                        out.write(record.remoteHandle.copyBytes())
                        out.writeInt(record.state.ordinal)
                        out.writeInt(record.characteristics.algorithm.ordinal)
                        out.writeInt(record.characteristics.curve.ordinal)
                        writeEnums(out, record.characteristics.purposes)
                        writeEnums(out, record.characteristics.digests)
                        out.writeInt(record.characteristics.securityLevel.ordinal)
                        val chain = record.certificateChain()
                        out.writeInt(chain.size)
                        chain.forEach {
                            out.writeInt(it.size)
                            out.write(it)
                        }
                    }
                }
                .toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(body)
        return body + digest
    }

    fun decode(encoded: ByteArray): CandidateKeyRecord {
        require(encoded.size in 100..(524_288 + 4096))
        val body = encoded.copyOf(encoded.size - 32)
        val digest = encoded.copyOfRange(encoded.size - 32, encoded.size)
        require(MessageDigest.getInstance("SHA-256").digest(body).contentEquals(digest))
        return DataInputStream(ByteArrayInputStream(body)).use { input ->
            require(input.readInt() == MAGIC)
            val version = input.readInt()
            require(version in 1..VERSION)
            val id = CandidateKeyId(input.readInt(), input.readLong(), input.readUTF())
            val identity = IdentityHash.of(ByteArray(32).also(input::readFully))
            val donorEpoch = input.readLong()
            val profileEpoch = input.readLong()
            val handle = RemoteKeyHandle.of(ByteArray(16).also(input::readFully))
            val states = CandidateKeyState.entries
            val stateIndex = input.readInt()
            require(stateIndex in states.indices)
            val characteristics =
                if (version == 1) {
                    CandidateCharacteristics.foreground()
                } else {
                    CandidateCharacteristics(
                        enumValue<CandidateAlgorithm>(input.readInt()),
                        enumValue<CandidateCurve>(input.readInt()),
                        readEnums<CandidatePurpose>(input),
                        readEnums<CandidateDigest>(input),
                        enumValue<CandidateSecurityLevel>(input.readInt()),
                    )
                }
            val count = input.readInt()
            require(count in 2..20)
            var total = 0
            val chain =
                List(count) {
                    val length = input.readInt()
                    require(length in 1..65_536)
                    total += length
                    require(total <= 524_288)
                    ByteArray(length).also(input::readFully)
                }
            require(input.available() == 0)
            CandidateKeyRecord(
                id,
                identity,
                donorEpoch,
                profileEpoch,
                handle,
                chain,
                characteristics,
                states[stateIndex],
            )
        }
    }

    private fun <T : Enum<T>> writeEnums(out: DataOutputStream, values: Set<T>) {
        out.writeInt(values.size)
        values.sortedBy(Enum<T>::ordinal).forEach { out.writeInt(it.ordinal) }
    }

    private inline fun <reified T : Enum<T>> readEnums(input: DataInputStream): Set<T> {
        val count = input.readInt()
        val entries = enumValues<T>()
        require(count in 1..entries.size)
        return List(count) { enumValue<T>(input.readInt()) }
            .toSet()
            .also { require(it.size == count) }
    }

    private inline fun <reified T : Enum<T>> enumValue(index: Int): T =
        enumValues<T>().let {
            require(index in it.indices)
            it[index]
        }
}

private object CandidateOperationCodec {
    private const val MAGIC = 0x524b4f31
    private const val VERSION = 1

    fun encode(record: CandidateOperationRecord): ByteArray {
        val body =
            ByteArrayOutputStream()
                .also { bytes ->
                    DataOutputStream(bytes).use { out ->
                        out.writeInt(MAGIC)
                        out.writeInt(VERSION)
                        out.write(record.handle.copyBytes())
                        out.writeInt(record.keyId.uid)
                        out.writeLong(record.keyId.namespace)
                        out.writeUTF(record.keyId.alias)
                        out.writeInt(record.state.ordinal)
                    }
                }
                .toByteArray()
        return body + MessageDigest.getInstance("SHA-256").digest(body)
    }

    fun decode(encoded: ByteArray): CandidateOperationRecord {
        require(encoded.size in 65..512)
        val body = encoded.copyOf(encoded.size - 32)
        val digest = encoded.copyOfRange(encoded.size - 32, encoded.size)
        require(MessageDigest.getInstance("SHA-256").digest(body).contentEquals(digest))
        return DataInputStream(ByteArrayInputStream(body)).use { input ->
            require(input.readInt() == MAGIC)
            require(input.readInt() == VERSION)
            val handle = RemoteOperationHandle.of(ByteArray(16).also(input::readFully))
            val keyId = CandidateKeyId(input.readInt(), input.readLong(), input.readUTF())
            val states = CandidateOperationState.entries
            val stateIndex = input.readInt()
            require(stateIndex in states.indices)
            require(input.available() == 0)
            CandidateOperationRecord(handle, keyId, states[stateIndex])
        }
    }
}
