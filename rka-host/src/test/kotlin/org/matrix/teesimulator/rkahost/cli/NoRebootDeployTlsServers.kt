package org.matrix.teesimulator.rkahost.cli

import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.LockSupport

internal class FixtureTlsServers(private val root: Path) : java.io.Closeable {
    private val processes = mutableListOf<Process>()
    private val activeProcesses = mutableListOf<Process>()

    init {
        Files.createDirectories(root)
        listOf("DONOR_A", "CANDIDATE_B", "ALTERNATE").forEach { identity ->
            val identityRoot = root.resolve(identity)
            Files.createDirectory(identityRoot)
            val generated =
                ProcessBuilder(
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "ec",
                        "-pkeyopt",
                        "ec_paramgen_curve:P-256",
                        "-nodes",
                        "-days",
                        "1",
                        "-subj",
                        "/CN=$identity",
                        "-keyout",
                        identityRoot.resolve("server.key").toString(),
                        "-out",
                        identityRoot.resolve("server.pem").toString(),
                    )
                    .redirectErrorStream(true)
                    .start()
            generated.inputStream.use { it.readAllBytes() }
            check(generated.waitFor() == 0)
            val pin =
                ProcessBuilder(
                        "bash",
                        "-c",
                        "openssl x509 -in \"${identityRoot.resolve("server.pem")}\" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print ${'$'}1}'",
                    )
                    .redirectErrorStream(true)
                    .start()
            val encodedPin = pin.inputStream.bufferedReader().readText()
            check(pin.waitFor() == 0)
            Files.writeString(identityRoot.resolve("server.pin"), encodedPin)
        }
    }

    fun <T> withServers(mutation: FixtureMutation?, action: () -> T): T {
        start(mutation)
        return try {
            action()
        } finally {
            stop()
        }
    }

    fun allStopped(): Boolean = processes.all { !it.isAlive }

    override fun close() {
        stop()
    }

    private fun start(mutation: FixtureMutation?) {
        check(activeProcesses.isEmpty())
        val protocol = if (mutation == FixtureMutation.TLS12_ONLY) "-tls1_2" else "-tls1_3"
        val donorIdentity =
            if (mutation == FixtureMutation.MISMATCH_CANDIDATE_PIN) "ALTERNATE" else "DONOR_A"
        startServer("127.0.0.1", donorIdentity, protocol)
        startServer("127.0.0.2", "CANDIDATE_B", protocol)
        awaitListener("127.0.0.1", activeProcesses[0])
        awaitListener("127.0.0.2", activeProcesses[1])
    }

    private fun startServer(address: String, identity: String, protocol: String) {
        val identityRoot = root.resolve(identity)
        val log = root.resolve("server-${address.substringAfterLast('.')}.log").toFile()
        val process =
            ProcessBuilder(
                    "openssl",
                    "s_server",
                    "-accept",
                    "$address:37373",
                    "-cert",
                    identityRoot.resolve("server.pem").toString(),
                    "-key",
                    identityRoot.resolve("server.key").toString(),
                    protocol,
                    "-quiet",
                )
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log))
                .redirectError(ProcessBuilder.Redirect.appendTo(log))
                .start()
        processes += process
        activeProcesses += process
    }

    private fun awaitListener(address: String, process: Process) {
        repeat(200) {
            check(process.isAlive) { "TLS fixture server exited before listening on $address" }
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(address, 37373), 25)
                    return
                }
            } catch (_: java.io.IOException) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5))
            }
        }
        error("TLS fixture server did not listen on $address")
    }

    private fun stop() {
        activeProcesses.forEach { process ->
            process.destroy()
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                check(process.waitFor(2, TimeUnit.SECONDS))
            }
        }
        activeProcesses.clear()
    }
}
