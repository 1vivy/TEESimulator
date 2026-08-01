package org.matrix.teesimulator.rkahost.cli

import com.sun.jna.Library
import com.sun.jna.Native
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

data class DescriptorFacts(
    val name: String,
    val seals: Int,
    val accessMode: Int,
    val regular: Boolean,
    val size: Long,
)

object DescriptorPolicy {
    private const val REQUIRED_SEALS = 15

    fun validate(facts: DescriptorFacts) {
        if (facts.name != "/memfd:rka-device-pair (deleted)") {
            throw HostCliException("PAIR_FD_NAME_INVALID")
        }
        if (facts.seals and REQUIRED_SEALS != REQUIRED_SEALS) {
            throw HostCliException("PAIR_FD_UNSEALED")
        }
        if (facts.accessMode != 0) throw HostCliException("PAIR_FD_WRITABLE")
        if (!facts.regular) throw HostCliException("PAIR_FD_TYPE_INVALID")
        if (facts.size !in 1..65_536) throw HostCliException("PAIR_FD_SIZE_INVALID")
    }
}

object NativePairDescriptor {
    private const val FD = 3
    private const val F_GETFL = 3
    private const val F_GET_SEALS = 1034
    private const val O_ACCMODE = 3

    fun readOnce(): DevicePairSnapshot {
        if (System.getenv("RKA_DEVICE_PAIR_FD") != FD.toString()) {
            throw HostCliException("PAIR_FD_MISSING")
        }
        val fdPath = Path.of("/proc/self/fd/$FD")
        val facts =
            try {
                val flags = LibC.INSTANCE.fcntl(FD, F_GETFL)
                val seals = LibC.INSTANCE.fcntl(FD, F_GET_SEALS)
                if (flags < 0 || seals < 0) throw HostCliException("PAIR_FD_INVALID")
                val attributes = Files.readAttributes(fdPath, BasicFileAttributes::class.java)
                DescriptorFacts(
                    Files.readSymbolicLink(fdPath).toString(),
                    seals,
                    flags and O_ACCMODE,
                    attributes.isRegularFile,
                    attributes.size(),
                )
            } catch (failure: HostCliException) {
                throw failure
            } catch (_: Exception) {
                throw HostCliException("PAIR_FD_INVALID")
            }
        DescriptorPolicy.validate(facts)
        val raw =
            try {
                Files.newInputStream(fdPath).use { stream ->
                    val bytes = stream.readNBytes(65_537)
                    if (bytes.size.toLong() != facts.size) {
                        throw HostCliException("PAIR_FD_SIZE_MISMATCH")
                    }
                    bytes.toString(Charsets.UTF_8)
                }
            } catch (failure: HostCliException) {
                throw failure
            } catch (_: Exception) {
                throw HostCliException("PAIR_FD_INVALID")
            }
        return DevicePairSnapshot.parse(raw)
    }

    private interface LibC : Library {
        fun fcntl(fd: Int, command: Int): Int

        companion object {
            val INSTANCE: LibC = Native.load("c", LibC::class.java)
        }
    }
}
