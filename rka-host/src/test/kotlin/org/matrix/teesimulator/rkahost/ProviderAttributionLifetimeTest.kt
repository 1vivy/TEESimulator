package org.matrix.teesimulator.rkahost

import java.nio.file.Path
import kotlin.io.path.readText
import org.junit.Assert.assertTrue
import org.junit.Test

class ProviderAttributionLifetimeTest {
    @Test
    fun capturesBinderCallerBeforePipeThreadStarts() {
        val source =
            Path.of(
                    "..",
                    "rka-fixture",
                    "src",
                    "debug",
                    "kotlin",
                    "org",
                    "matrix",
                    "teesimulator",
                    "rkafixture",
                    "DebugCommandProvider.kt",
                )
                .readText()

        val pipeThreadStart = source.indexOf("Thread {")
        val pipeThread =
            source.substring(pipeThreadStart, source.indexOf("\"execute\"", pipeThreadStart))

        assertTrue(source.indexOf("val caller = captureCaller()") < pipeThreadStart)
        assertTrue(!pipeThread.contains("Binder.getCallingUid()"))
        assertTrue(!pipeThread.contains("callingPackage"))
    }
}
