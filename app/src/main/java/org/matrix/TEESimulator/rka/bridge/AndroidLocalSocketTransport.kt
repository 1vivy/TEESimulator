package org.matrix.TEESimulator.rka.bridge

import android.net.LocalSocket
import java.io.InputStream
import java.io.OutputStream

class AndroidLocalSocketTransport(private val socket: LocalSocket) : BridgeTransport {
    override fun peerCredentials(): PeerCredentials {
        val credentials = socket.peerCredentials
        return PeerCredentials(credentials.uid, credentials.gid, credentials.pid)
    }

    override fun input(): InputStream = socket.inputStream

    override fun output(): OutputStream = socket.outputStream

    override fun close() {
        socket.close()
    }
}
