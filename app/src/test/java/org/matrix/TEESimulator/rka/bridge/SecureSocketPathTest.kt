package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureSocketPathTest {
    @Test
    fun create_chown_chmod_label_and_bind_failures_stay_typed() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        val cases =
            listOf(
                "create" to BridgeError.SocketCreateDenied,
                "chown" to BridgeError.SocketChownDenied,
                "chmod" to BridgeError.SocketChmodDenied,
                "label" to BridgeError.SocketLabelDenied,
            )
        for ((failure, expected) in cases) {
            val operations = FakePathOperations(failure)
            assertEquals(expected, SecureSocketPath(operations).prepare(socket).failure())
        }
        val operations = FakePathOperations()
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(operations),
                BridgeServerBinder { BridgeResult.Failure(BridgeError.SocketBindDenied) },
            )
        assertEquals(BridgeError.SocketBindDenied, result.failure())
    }

    @Test
    fun parent_inode_replacement_after_bind_is_rejected() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        val operations = FakePathOperations()
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(operations),
                BridgeServerBinder {
                    operations.createSocket(socket)
                    operations.replaceDirectoryInode()
                    BridgeResult.Success(FakeBinding { operations.bindingClosed = true })
                },
            )

        assertEquals(BridgeError.SocketPathChanged, result.failure())
    }

    @Test
    fun cleanup_unlinks_only_the_exact_bound_socket_inode() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        val operations = FakePathOperations()
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(operations),
                BridgeServerBinder {
                    operations.createSocket(socket)
                    BridgeResult.Success(FakeBinding { operations.bindingClosed = true })
                },
            )
        val server = (result as BridgeResult.Success).value
        operations.replaceSocketInode()

        server.close()

        assertFalse(operations.deleted)
        assertTrue(operations.bindingClosed)
    }

    private fun BridgeResult<*>.failure(): BridgeError = (this as BridgeResult.Failure).error

    private class FakeBinding(private val onClose: () -> Unit) : BridgeServerBinding {
        override fun accept(): BridgeTransport = error("unused")

        override fun close() {
            onClose()
        }
    }

    private class FakePathOperations(private val failAt: String? = null) :
        BridgeSocketPathOperations {
        private val directory = Path.of("/runtime/run/sockets")
        private var directoryIdentity = BridgePathIdentity(10, 0, 0, 0x1c0, true, false, false)
        private var socketIdentity = BridgePathIdentity(20, 0, 0, 0x180, false, true, false)
        private var socketExists = false
        var deleted = false
        var bindingClosed = false

        override fun createDirectories(path: Path) {
            if (failAt == "create") error("create denied")
        }

        override fun exists(path: Path): Boolean = socketExists

        override fun rejectSymlinkAncestors(path: Path) = Unit

        override fun chown(path: Path, uid: Int, gid: Int) {
            if (failAt == "chown") error("chown denied")
        }

        override fun chmod(path: Path, mode: Int) {
            if (failAt == "chmod") error("chmod denied")
        }

        override fun restoreLabel(path: Path): Boolean {
            if (failAt == "label") return false
            return true
        }

        override fun stat(path: Path): BridgePathIdentity =
            if (path == directory) {
                directoryIdentity
            } else {
                check(socketExists)
                socketIdentity
            }

        override fun delete(path: Path) {
            deleted = true
        }

        fun createSocket(path: Path) {
            socketExists = true
            socketIdentity = socketIdentity.copy(inode = 20)
        }

        fun replaceDirectoryInode() {
            directoryIdentity = directoryIdentity.copy(inode = 11)
        }

        fun replaceSocketInode() {
            socketIdentity = socketIdentity.copy(inode = 21)
        }
    }
}
