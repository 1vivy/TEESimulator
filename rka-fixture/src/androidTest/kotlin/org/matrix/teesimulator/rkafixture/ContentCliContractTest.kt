package org.matrix.teesimulator.rkafixture

import android.app.Instrumentation
import android.net.Uri
import android.os.ParcelFileDescriptor
import junit.framework.TestCase

class ContentCliContractTest : TestCase() {
    fun testWriteReadDeleteWithShellDumpAndForegroundRequest() {
        val nonce = "00112233445566778899aabbccddeeff"
        val request = byteArrayOf(0x41, 0, 0x42, 0xff.toByte())
        val requestUri = "content://org.matrix.teesimulator.rkafixture.commands/v1/request/$nonce"
        val executeUri = "content://org.matrix.teesimulator.rkafixture.commands/v1/execute/$nonce"
        val statusUri = "content://org.matrix.teesimulator.rkafixture.commands/v1/status/$nonce"
        val backgroundUri =
            "content://org.matrix.teesimulator.rkafixture.commands/v1/background/$nonce"
        shell("content write --uri $requestUri", request)
        val response = shell("content read --uri $executeUri")
        assertEquals("RKA2", response.copyOfRange(0, 4).decodeToString())
        assertEquals(nonce, response.copyOfRange(4, 20).joinToString("") { "%02x".format(it) })
        assertTrue(response.copyOfRange(20, response.size).contentEquals(request))
        val statusResponse = shell("content read --uri $statusUri")
        val status = statusResponse.copyOfRange(20, statusResponse.size).decodeToString()
        assertTrue(status.contains("uid=2000"))
        assertTrue(status.contains("pkg=com.android.shell"))
        val backgroundResponse = shell("content read --uri $backgroundUri")
        assertEquals(
            "FOREGROUND_START_REQUESTED",
            backgroundResponse.copyOfRange(20, backgroundResponse.size).decodeToString(),
        )
        shell("content delete --uri $requestUri")
    }

    fun testDirectAppCallerIsDeniedByDumpPermission() {
        val uri =
            Uri.parse(
                "content://org.matrix.teesimulator.rkafixture.commands/v1/status/00112233445566778899aabbccddeeff"
            )
        try {
            instrumentation().context.contentResolver.openInputStream(uri)?.close()
        } catch (_: SecurityException) {
            return
        }
        fail("DUMP-protected provider accepted an app caller")
    }

    private fun shell(command: String, stdin: ByteArray = ByteArray(0)): ByteArray {
        val pipes = instrumentation().uiAutomation.executeShellCommandRwe(command)
        ParcelFileDescriptor.AutoCloseOutputStream(pipes[0]).use { it.write(stdin) }
        return ParcelFileDescriptor.AutoCloseInputStream(pipes[1]).use { it.readBytes() }
    }

    private fun instrumentation(): Instrumentation =
        Class.forName("androidx.test.platform.app.InstrumentationRegistry")
            .getMethod("getInstrumentation")
            .invoke(null) as Instrumentation
}
