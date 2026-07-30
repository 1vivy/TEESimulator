package org.matrix.TEESimulator.rka.bridge

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.system.Os
import java.io.Closeable
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

class DonorBridgeServer
private constructor(private val server: LocalServerSocket, private val boundSocket: LocalSocket) :
    Closeable {
    fun accept(): BridgeTransport = AndroidLocalSocketTransport(server.accept())

    override fun close() {
        server.close()
        boundSocket.close()
    }

    companion object {
        fun bind(socketPath: Path): DonorBridgeServer {
            validateRootDirectory(socketPath.parent)
            require(!Files.exists(socketPath, LinkOption.NOFOLLOW_LINKS))
            val bound = LocalSocket()
            try {
                bound.bind(
                    LocalSocketAddress(
                        socketPath.toString(),
                        LocalSocketAddress.Namespace.FILESYSTEM,
                    )
                )
                Os.chmod(socketPath.toString(), 0x180)
                return DonorBridgeServer(LocalServerSocket(bound.fileDescriptor), bound)
            } catch (error: Throwable) {
                runCatching { bound.close() }
                throw error
            }
        }
    }
}

object CandidateBridgeConnector {
    fun connect(socketPath: Path): BridgeTransport {
        validateRootDirectory(socketPath.parent)
        require(!Files.isSymbolicLink(socketPath))
        val socket = LocalSocket()
        try {
            socket.connect(
                LocalSocketAddress(socketPath.toString(), LocalSocketAddress.Namespace.FILESYSTEM)
            )
            return AndroidLocalSocketTransport(socket)
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }
}

private fun validateRootDirectory(directory: Path) {
    require(!Files.isSymbolicLink(directory))
    val metadata = Files.readAttributes(directory, "unix:uid,gid,mode", LinkOption.NOFOLLOW_LINKS)
    require((metadata["uid"] as Number).toInt() == 0)
    require((metadata["gid"] as Number).toInt() == 0)
    require((metadata["mode"] as Number).toInt() and 0x1ff == 0x1c0)
}
