package org.matrix.teesimulator.physicalharness

import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class AtomicFileDonorStateBlobStoreTest {
    private val directory = createTempDirectory("donor-state-store").toFile()
    private val facade = FakeAtomicFileFacade(directory)
    private val store = AtomicFileDonorStateBlobStore(facade)

    @AfterTest
    fun cleanUp() {
        directory.deleteRecursively()
    }

    @Test
    fun missingBlobIsNullAndSuccessfulReadsAndWritesAreDefensive() {
        assertNull(store.read())
        assertEquals(2, facade.presenceChecks)
        val source = testBytes(128, 1)
        val expected = source.copyOf()

        store.write(source)
        source.fill(0)
        val first = store.read()!!
        first.fill(0)

        assertContentEquals(expected, store.read())
        assertEquals(1, facade.finishedWrites)
        assertEquals(1, facade.outputCloseCalls)
    }

    @Test
    fun fileNotFoundIsNullOnlyWhenAbsenceIsConfirmedBeforeAndAfterOpen() {
        val openFailure = FileNotFoundException("simulated I/O failure")
        facade.openReadFailure = openFailure
        facade.presenceResults.addAll(listOf(true, true))
        assertSame(openFailure, assertFailsWith<FileNotFoundException> { store.read() })

        facade.presenceResults.addAll(listOf(false, true))
        assertSame(openFailure, assertFailsWith<FileNotFoundException> { store.read() })
    }

    @Test
    fun recoveryArtifactPresenceIsConservativelyNonmissing() {
        val openFailure = FileNotFoundException("simulated recovery failure")
        facade.openReadFailure = openFailure
        facade.recoveryArtifactPresent = true

        assertSame(openFailure, assertFailsWith<FileNotFoundException> { store.read() })
    }

    @Test
    fun artifactProbeReusesFacadePresenceWithoutOpeningStateBytes() {
        assertFalse(store.hasArtifacts())
        facade.recoveryArtifactPresent = true
        assertTrue(store.hasArtifacts())

        assertEquals(2, facade.presenceChecks)
        assertEquals(0, facade.openReadCalls)
    }

    @Test
    fun zeroProgressBulkReadFailsWithoutRetrying() {
        store.write(testBytes(64, 7))
        facade.zeroProgressRead = true

        assertFailsWith<DonorStateBlobStoreException.UnexpectedLength> { store.read() }
        assertEquals(1, facade.bulkReadCalls)
    }

    @Test
    fun previousCommitSurvivesStartWriteAndFinishFailures() {
        val previous = testBytes(64, 2)
        store.write(previous)

        FailurePoint.entries.forEach { failurePoint ->
            facade.failurePoint = failurePoint
            val expectedFailure = facade.failure
            val failure = assertFailsWith<TestFailure> { store.write(testBytes(96, 3)) }

            assertSame(expectedFailure, failure)
            facade.failurePoint = null
            assertContentEquals(previous, store.read())
        }
    }

    @Test
    fun failWriteFailureIsSuppressedWithoutReplacingTheOriginalFailure() {
        val previous = testBytes(64, 4)
        store.write(previous)
        facade.failurePoint = FailurePoint.WRITE
        facade.failCleanup = true

        val failure = assertFailsWith<TestFailure> { store.write(testBytes(96, 5)) }

        assertSame(facade.failure, failure)
        assertEquals(1, failure.suppressed.size)
        assertSame(facade.cleanupFailure, failure.suppressed.single())
        facade.failurePoint = null
        facade.failCleanup = false
        assertContentEquals(previous, store.read())
    }

    @Test
    fun oversizedWritesFailBeforeStartAndOversizedFilesFailBeforeAllocation() {
        assertFailsWith<DonorStateBlobStoreException.OversizedBlob> {
            store.write(ByteArray(DonorStateCodec.MAX_FILE_BYTES + 1))
        }
        assertEquals(0, facade.startedWrites)

        RandomAccessFile(facade.committedFile, "rw").use {
            it.setLength(DonorStateCodec.MAX_FILE_BYTES.toLong() + 1)
        }
        assertFailsWith<DonorStateBlobStoreException.OversizedBlob> { store.read() }
    }

    @Test
    fun everyReadAndWriteTransactionIsSerialized() {
        store.write(testBytes(64, 6))
        facade.transactionDelayMillis = 5
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(8)
        val futures =
            List(24) { index ->
                pool.submit {
                    start.await()
                    if (index % 3 == 0) store.write(testBytes(64, index)) else store.read()
                }
            }

        start.countDown()
        futures.forEach { it.get(5, TimeUnit.SECONDS) }
        pool.shutdown()

        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
        assertEquals(1, facade.maximumConcurrentTransactions.get())
        assertEquals(0, facade.activeTransactions.get())
    }

    private enum class FailurePoint {
        START,
        WRITE,
        FINISH,
    }

    private class TestFailure : RuntimeException()

    private class CleanupFailure : RuntimeException()

    private class FakeAtomicFileFacade(directory: File) : DonorAtomicFileFacade {
        val committedFile = File(directory, "committed")
        private val pendingFile = File(directory, "pending")
        val failure = TestFailure()
        val cleanupFailure = CleanupFailure()
        val activeTransactions = AtomicInteger()
        val maximumConcurrentTransactions = AtomicInteger()
        var failurePoint: FailurePoint? = null
        var failCleanup = false
        var transactionDelayMillis = 0L
        var startedWrites = 0
        var finishedWrites = 0
        var outputCloseCalls = 0
        var presenceChecks = 0
        var openReadFailure: FileNotFoundException? = null
        var openReadCalls = 0
        var recoveryArtifactPresent = false
        var zeroProgressRead = false
        var bulkReadCalls = 0
        val presenceResults = ArrayDeque<Boolean>()

        override fun isPresent(): Boolean {
            presenceChecks += 1
            return presenceResults.removeFirstOrNull()
                ?: (committedFile.exists() || recoveryArtifactPresent)
        }

        override fun openRead(): FileInputStream {
            openReadCalls += 1
            openReadFailure?.let { throw it }
            if (!committedFile.exists()) throw FileNotFoundException()
            enterTransaction()
            return TrackingFileInputStream(
                committedFile,
                zeroProgressRead,
                onBulkRead = { bulkReadCalls += 1 },
                onClose = ::leaveTransaction,
            )
        }

        override fun startWrite(): FileOutputStream {
            if (failurePoint == FailurePoint.START) throw failure
            enterTransaction()
            startedWrites += 1
            return TrackingFileOutputStream(
                pendingFile,
                failWrite = { failurePoint == FailurePoint.WRITE },
                onClose = { outputCloseCalls += 1 },
                failure,
            )
        }

        override fun finishWrite(stream: FileOutputStream) {
            if (failurePoint == FailurePoint.FINISH) throw failure
            stream.close()
            Files.move(
                pendingFile.toPath(),
                committedFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
            )
            finishedWrites += 1
            leaveTransaction()
        }

        override fun failWrite(stream: FileOutputStream) {
            try {
                stream.close()
                pendingFile.delete()
            } finally {
                leaveTransaction()
            }
            if (failCleanup) throw cleanupFailure
        }

        private fun enterTransaction() {
            val active = activeTransactions.incrementAndGet()
            maximumConcurrentTransactions.accumulateAndGet(active, ::maxOf)
            if (transactionDelayMillis > 0) Thread.sleep(transactionDelayMillis)
        }

        private fun leaveTransaction() {
            activeTransactions.decrementAndGet()
        }
    }

    private class TrackingFileInputStream(
        file: File,
        private val zeroProgress: Boolean,
        private val onBulkRead: () -> Unit,
        private val onClose: () -> Unit,
    ) : FileInputStream(file) {
        private var closed = false

        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            if (!zeroProgress) return super.read(bytes, offset, length)
            onBulkRead()
            if (channel.position() == 0L) {
                channel.position(1L)
                return 0
            }
            throw AssertionError("zero-progress read was retried")
        }

        override fun close() {
            super.close()
            if (!closed) {
                closed = true
                onClose()
            }
        }
    }

    private class TrackingFileOutputStream(
        file: File,
        private val failWrite: () -> Boolean,
        private val onClose: () -> Unit,
        private val failure: TestFailure,
    ) : FileOutputStream(file) {
        private var closed = false

        override fun write(bytes: ByteArray) {
            if (failWrite()) {
                super.write(bytes, 0, bytes.size / 2)
                throw failure
            }
            super.write(bytes)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (failWrite()) {
                super.write(bytes, offset, length / 2)
                throw failure
            }
            super.write(bytes, offset, length)
        }

        override fun close() {
            super.close()
            if (!closed) {
                closed = true
                onClose()
            }
        }
    }
}
