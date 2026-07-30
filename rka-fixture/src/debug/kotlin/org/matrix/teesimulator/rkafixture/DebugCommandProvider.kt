package org.matrix.teesimulator.rkafixture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.util.concurrent.ConcurrentHashMap

class DebugCommandProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String = "application/octet-stream"

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val route = route(uri)
        val caller = captureCaller()
        return when (route.kind) {
            "request" -> {
                if (!mode.contains('w')) throw FileNotFoundException("write required")
                val pipe = ParcelFileDescriptor.createPipe()
                Thread {
                        ParcelFileDescriptor.AutoCloseInputStream(pipe[0]).use { input ->
                            requests[route.nonce] = input.readBounded()
                            callers[route.nonce] = caller
                        }
                    }
                    .start()
                pipe[1]
            }
            "execute" -> responsePipe(route.nonce, requests[route.nonce] ?: ByteArray(0))
            "status" ->
                responsePipe(
                    route.nonce,
                    callers[route.nonce]?.status?.encodeToByteArray() ?: ByteArray(0),
                )
            "background" -> {
                val providerContext =
                    context ?: throw IllegalStateException("PROVIDER_CONTEXT_MISSING")
                providerContext.startForegroundService(
                    DebugCommandForegroundService.intent(
                        providerContext,
                        caller.uid,
                        caller.packageName,
                    )
                )
                responsePipe(route.nonce, "FOREGROUND_START_REQUESTED".encodeToByteArray())
            }
            else -> throw FileNotFoundException("route")
        }
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int {
        val route = route(uri)
        if (route.kind != "request") throw FileNotFoundException("request required")
        callers.remove(route.nonce)
        return if (requests.remove(route.nonce) != null) 1 else 0
    }

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<String>?,
    ): Int = 0

    private fun responsePipe(nonce: String, payload: ByteArray): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { output ->
                    output.write(magic)
                    output.write(nonce.hexToBytes())
                    output.write(payload)
                }
            }
            .start()
        return pipe[0]
    }

    private fun captureCaller(): Caller {
        val uid = Binder.getCallingUid()
        val packageName = callingPackage ?: throw SecurityException("CALLER_PACKAGE_MISSING")
        if (uid != Process.SHELL_UID || packageName != SHELL_PACKAGE) {
            throw SecurityException("CALLER_NOT_SHELL")
        }
        return Caller(uid, packageName)
    }

    private fun route(uri: Uri): Route {
        val parts = uri.pathSegments
        if (
            uri.authority != AUTHORITY ||
                parts.size != 3 ||
                parts[0] != "v1" ||
                !noncePattern.matches(parts[2])
        ) {
            throw FileNotFoundException("invalid fixture uri")
        }
        return Route(parts[1], parts[2])
    }

    private fun java.io.InputStream.readBounded(): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = read(buffer)
            if (count < 0) return output.toByteArray()
            if (output.size() + count > MAX_BYTES) throw FileNotFoundException("request too large")
            output.write(buffer, 0, count)
        }
    }

    private fun String.hexToBytes(): ByteArray =
        ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }

    private data class Route(val kind: String, val nonce: String)

    private data class Caller(val uid: Int, val packageName: String) {
        val status = "uid=$uid;pkg=$packageName;permission=DUMP"
    }

    companion object {
        private const val AUTHORITY = "org.matrix.teesimulator.rkafixture.commands"
        private const val MAX_BYTES = 2 * 1024 * 1024
        private const val SHELL_PACKAGE = "com.android.shell"
        private val magic =
            byteArrayOf('R'.code.toByte(), 'K'.code.toByte(), 'A'.code.toByte(), '2'.code.toByte())
        private val noncePattern = Regex("[0-9a-f]{32}")
        private val requests = ConcurrentHashMap<String, ByteArray>()
        private val callers = ConcurrentHashMap<String, Caller>()
    }
}

class DebugCommandForegroundService : Service() {
    override fun onBind(intent: Intent?) = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (
            intent?.getIntExtra("caller_uid", -1) != Process.SHELL_UID ||
                intent.getStringExtra("caller_package") != "com.android.shell"
        ) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(
            NotificationChannel("rka-debug", "RKA debug", NotificationManager.IMPORTANCE_MIN)
        )
        startForeground(
            4,
            Notification.Builder(this, "rka-debug")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("RKA debug")
                .build(),
        )
        stopSelf(startId)
        return START_NOT_STICKY
    }

    companion object {
        fun intent(
            context: android.content.Context,
            callerUid: Int,
            callerPackage: String,
        ): Intent =
            Intent(context, DebugCommandForegroundService::class.java)
                .putExtra("caller_uid", callerUid)
                .putExtra("caller_package", callerPackage)
    }
}
