package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureSocketPathTest {
    @Test
    fun directory_and_bound_socket_failures_stay_typed() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        assertEquals(
            BridgeError.SocketCreateDenied,
            SecureSocketPath(
                    BridgeSocketPathOperations {
                        BridgeResult.Failure(BridgeError.SocketCreateDenied)
                    }
                )
                .open(socket)
                .failure(),
        )
        val directory = FakeDirectory(socket, secureError = BridgeError.SocketLabelDenied)
        assertEquals(
            BridgeError.SocketLabelDenied,
            SecureSocketPath(BridgeSocketPathOperations { BridgeResult.Success(directory) })
                .open(socket)
                .failure(),
        )
        val validDirectory = FakeDirectory(socket)
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(
                    BridgeSocketPathOperations { BridgeResult.Success(validDirectory) }
                ),
                BridgeServerBinder {
                    validDirectory.createOwnedSocket()
                    BridgeResult.Success(FakeBinding(chmodError = BridgeError.SocketChmodDenied))
                },
            )
        assertEquals(BridgeError.SocketChmodDenied, result.failure())
    }

    @Test
    fun ancestor_or_leaf_swap_between_each_phase_is_rejected_without_competitor_deletion() {
        for (phase in SwapPhase.entries) {
            val socket = Path.of("/runtime/run/sockets/broker.sock")
            val directory = FakeDirectory(socket, swapPhase = phase)
            val result =
                DonorBridgeServer.bind(
                    socket,
                    SecureSocketPath(
                        BridgeSocketPathOperations { BridgeResult.Success(directory) }
                    ),
                    BridgeServerBinder {
                        directory.createOwnedSocket()
                        if (phase == SwapPhase.AFTER_BIND) directory.insertCompetitor()
                        BridgeResult.Success(
                            FakeBinding(
                                onChown = {
                                    if (phase == SwapPhase.AFTER_CHOWN) {
                                        directory.insertCompetitor()
                                    }
                                },
                                onChmod = {
                                    if (phase == SwapPhase.AFTER_CHMOD) {
                                        directory.insertCompetitor()
                                    }
                                },
                            )
                        )
                    },
                )

            assertEquals("phase=$phase", BridgeError.SocketPathChanged, result.failure())
            assertFalse("phase=$phase deleted competitor", directory.deleted)
            assertTrue("phase=$phase competitor missing", directory.socketStillExists())
        }
    }

    @Test
    fun cleanup_unlinks_only_the_exact_bound_socket_inode() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        val directory = FakeDirectory(socket)
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(BridgeSocketPathOperations { BridgeResult.Success(directory) }),
                BridgeServerBinder {
                    directory.createOwnedSocket()
                    BridgeResult.Success(FakeBinding())
                },
            )
        val server = (result as BridgeResult.Success).value
        directory.insertCompetitor()

        server.close()

        assertFalse(directory.deleted)
        assertTrue(directory.closed)
    }

    @Test
    fun bind_failure_never_deletes_a_competing_socket() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        val directory = FakeDirectory(socket)

        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(BridgeSocketPathOperations { BridgeResult.Success(directory) }),
                BridgeServerBinder {
                    directory.insertCompetitor()
                    BridgeResult.Failure(BridgeError.SocketBindDenied)
                },
            )

        assertEquals(BridgeError.SocketBindDenied, result.failure())
        assertFalse("bind failure deleted a socket it never owned", directory.deleted)
        assertTrue(directory.socketStillExists())
    }

    private fun BridgeResult<*>.failure(): BridgeError = (this as BridgeResult.Failure).error

    private enum class SwapPhase {
        AFTER_BIND,
        AFTER_CHOWN,
        AFTER_CHMOD,
        DURING_LABEL,
        BEFORE_FINAL_INSPECT,
    }

    private class FakeBinding(
        private val chownError: BridgeError? = null,
        private val chmodError: BridgeError? = null,
        private val onChown: () -> Unit = {},
        private val onChmod: () -> Unit = {},
    ) : BridgeServerBinding {
        var closed = false

        override fun acceptTransport(): BridgeTransport = error("unused")

        override fun boundSocketInode(): Long = OWNED_INODE

        override fun chownBoundSocket(inode: Long): BridgeResult<Unit> =
            chownError?.let { BridgeResult.Failure(it) }
                ?: BridgeResult.Success(Unit).also { onChown() }

        override fun chmodBoundSocket(inode: Long): BridgeResult<Unit> =
            chmodError?.let { BridgeResult.Failure(it) }
                ?: BridgeResult.Success(Unit).also { onChmod() }

        override fun close() {
            closed = true
        }
    }

    private class FakeDirectory(
        override val anchoredSocketPath: Path,
        private val secureError: BridgeError? = null,
        private val swapPhase: SwapPhase? = null,
    ) : BridgeSocketDirectoryHandle {
        private var inode: Long? = null
        var deleted = false
        var closed = false

        override fun secureDirectory(): BridgeResult<Unit> =
            secureError?.let { BridgeResult.Failure(it) } ?: BridgeResult.Success(Unit)

        override fun inspectSocket(): BridgeResult<BridgePathIdentity> {
            if (swapPhase == SwapPhase.BEFORE_FINAL_INSPECT) insertCompetitor()
            val current = inode ?: return BridgeResult.Failure(BridgeError.SocketPathChanged)
            return BridgeResult.Success(
                BridgePathIdentity(
                    current,
                    0,
                    0,
                    0x180,
                    isDirectory = false,
                    isSocket = true,
                    context = "u:object_r:teesimulator_rka_socket:s0",
                )
            )
        }

        override fun verifySocketInode(inode: Long): BridgeResult<Unit> =
            if (this.inode == inode) {
                BridgeResult.Success(Unit)
            } else {
                BridgeResult.Failure(BridgeError.SocketPathChanged)
            }

        override fun labelExactSocket(inode: Long): BridgeResult<Unit> {
            if (swapPhase == SwapPhase.DURING_LABEL) insertCompetitor()
            return verifySocketInode(inode)
        }

        override fun deleteExactSocket(inode: Long) {
            if (this.inode == inode) {
                deleted = true
                this.inode = null
            }
        }

        override fun close() {
            closed = true
        }

        fun createOwnedSocket() {
            inode = OWNED_INODE
        }

        fun insertCompetitor() {
            inode = COMPETITOR_INODE
        }

        fun socketStillExists(): Boolean = inode != null
    }

    private companion object {
        const val OWNED_INODE = 20L
        const val COMPETITOR_INODE = 21L
    }
}
