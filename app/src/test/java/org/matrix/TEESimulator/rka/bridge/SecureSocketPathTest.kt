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
        val validDirectory = FakeDirectory(socket, nodeChmodError = BridgeError.SocketChmodDenied)
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(
                    BridgeSocketPathOperations { BridgeResult.Success(validDirectory) }
                ),
                BridgeServerBinder {
                    validDirectory.createOwnedSocket()
                    BridgeResult.Success(FakeBinding(validDirectory.openedNode()))
                },
            )
        assertEquals(BridgeError.SocketChmodDenied, result.failure())
        val wrongContext = FakeDirectory(socket, nodeContextError = BridgeError.SocketLabelDenied)
        val contextResult =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(BridgeSocketPathOperations { BridgeResult.Success(wrongContext) }),
                BridgeServerBinder {
                    wrongContext.createOwnedSocket()
                    BridgeResult.Success(FakeBinding(wrongContext.openedNode()))
                },
            )
        assertEquals(BridgeError.SocketLabelDenied, contextResult.failure())
    }

    @Test
    fun ancestor_or_leaf_swap_between_each_phase_is_rejected_without_competitor_deletion() {
        for (phase in SwapPhase.entries.filter { it != SwapPhase.DURING_DELETE }) {
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
                        val binding = FakeBinding(directory.openedNode())
                        if (phase == SwapPhase.AFTER_BIND) directory.insertCompetitor()
                        BridgeResult.Success(binding)
                    },
                )

            assertEquals("phase=$phase", BridgeError.SocketPathChanged, result.failure())
            assertFalse("phase=$phase deleted competitor", directory.deleted)
            assertTrue("phase=$phase competitor missing", directory.socketStillExists())
        }
    }

    @Test
    fun cleanup_unlinks_only_the_exact_still_named_bound_socket() {
        val socket = Path.of("/runtime/run/sockets/broker.sock")
        val directory = FakeDirectory(socket, swapPhase = SwapPhase.DURING_DELETE)
        val result =
            DonorBridgeServer.bind(
                socket,
                SecureSocketPath(BridgeSocketPathOperations { BridgeResult.Success(directory) }),
                BridgeServerBinder {
                    directory.createOwnedSocket()
                    BridgeResult.Success(FakeBinding(directory.openedNode()))
                },
            )
        val server = (result as BridgeResult.Success).value

        server.close()

        assertFalse(directory.deleted)
        assertTrue(directory.socketStillExists())
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
        DURING_CONTEXT_VERIFY,
        BEFORE_FINAL_INSPECT,
        ANCESTOR_AFTER_OPEN,
        DURING_DELETE,
    }

    private class FakeBinding(override val socketNode: BridgeSocketNodeHandle) :
        BridgeServerBinding {
        override fun acceptTransport(): BridgeTransport = error("unused")

        override fun close() = Unit
    }

    private class FakeDirectory(
        override val anchoredSocketPath: Path,
        private val secureError: BridgeError? = null,
        private val swapPhase: SwapPhase? = null,
        private val nodeChmodError: BridgeError? = null,
        private val nodeContextError: BridgeError? = null,
    ) : BridgeSocketDirectoryHandle {
        private var namedInode: Long? = null
        private var node: FakeNode? = null
        var deleted = false
        var closed = false

        override fun secureDirectory(): BridgeResult<Unit> =
            secureError?.let { BridgeResult.Failure(it) } ?: BridgeResult.Success(Unit)

        override fun openSocketNode(): BridgeResult<BridgeSocketNodeHandle> =
            node?.let { BridgeResult.Success(it) }
                ?: BridgeResult.Failure(BridgeError.SocketPathChanged)

        override fun close() {
            closed = true
        }

        fun createOwnedSocket() {
            namedInode = OWNED_INODE
            node = FakeNode(this, OWNED_INODE)
        }

        fun openedNode(): BridgeSocketNodeHandle = requireNotNull(node)

        fun insertCompetitor() {
            namedInode = COMPETITOR_INODE
        }

        fun socketStillExists(): Boolean = namedInode != null

        private inner class FakeNode(private val owner: FakeDirectory, override val inode: Long) :
            BridgeSocketNodeHandle {
            override fun chownRoot(): BridgeResult<Unit> {
                if (swapPhase == SwapPhase.AFTER_CHOWN) insertCompetitor()
                return verifyStillNamed()
            }

            override fun chmodOwnerOnly(): BridgeResult<Unit> {
                if (nodeChmodError != null) return BridgeResult.Failure(nodeChmodError)
                if (swapPhase == SwapPhase.AFTER_CHMOD) insertCompetitor()
                return verifyStillNamed()
            }

            override fun verifyDedicatedContext(): BridgeResult<Unit> {
                if (nodeContextError != null) return BridgeResult.Failure(nodeContextError)
                if (swapPhase == SwapPhase.DURING_CONTEXT_VERIFY) insertCompetitor()
                return verifyStillNamed()
            }

            override fun inspect(): BridgeResult<BridgePathIdentity> {
                if (swapPhase == SwapPhase.BEFORE_FINAL_INSPECT) insertCompetitor()
                if (verifyStillNamed() is BridgeResult.Failure) {
                    return BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
                return BridgeResult.Success(
                    BridgePathIdentity(
                        inode,
                        0,
                        0,
                        0x180,
                        isDirectory = false,
                        isSocket = true,
                        context = "u:object_r:teesimulator_rka_socket:s0",
                    )
                )
            }

            override fun verifyStillNamed(): BridgeResult<Unit> {
                if (swapPhase == SwapPhase.ANCESTOR_AFTER_OPEN) insertCompetitor()
                return if (owner.namedInode == inode) {
                    BridgeResult.Success(Unit)
                } else {
                    BridgeResult.Failure(BridgeError.SocketPathChanged)
                }
            }

            override fun deleteIfStillNamed() {
                if (swapPhase == SwapPhase.DURING_DELETE) insertCompetitor()
                if (owner.namedInode == inode) {
                    deleted = true
                    owner.namedInode = null
                }
            }

            override fun close() = Unit
        }
    }

    private companion object {
        const val OWNED_INODE = 20L
        const val COMPETITOR_INODE = 21L
    }
}
