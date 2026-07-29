package org.matrix.teesimulator.rkafixture

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import java.io.FileNotFoundException
import java.io.IOException

class FixtureCommandProvider : ContentProvider() {
    private lateinit var runtime: FixtureProviderRuntime

    override fun onCreate(): Boolean {
        runtime = (requireContext().applicationContext as FixtureApplication).providerRuntime
        return true
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val route = authorizeOpen(uri, mode)
        return when (route) {
            is FixtureProviderRoute.Request -> uploadProxy(route.nonce)
            is FixtureProviderRoute.Execute -> responsePipe(route.nonce)
        }
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int {
        if (selection != null || selectionArgs != null) throw FileNotFoundException("INVALID_ROUTE")
        val route = authorizeDelete(uri)
        return if (runtime.cleanup(route.nonce)) 1 else 0
    }

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?,
    ): Cursor? = throw UnsupportedOperationException("query is unsupported")

    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException("insert is unsupported")

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<String>?,
    ): Int = throw UnsupportedOperationException("update is unsupported")

    override fun getType(uri: Uri): String? =
        throw UnsupportedOperationException("getType is unsupported")

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle =
        throw UnsupportedOperationException("call is unsupported")

    override fun call(authority: String, method: String, arg: String?, extras: Bundle?): Bundle =
        throw UnsupportedOperationException("call is unsupported")

    private fun uploadProxy(nonce: String): ParcelFileDescriptor =
        requireContext()
            .getSystemService(StorageManager::class.java)
            .openProxyFileDescriptor(
                ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_CREATE,
                UploadCallback(runtime.beginProxyUpload(nonce)),
                Handler(requireContext().mainLooper),
            )

    private fun responsePipe(nonce: String): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { output ->
                    try {
                        output.write(runtime.executeResponse(nonce).encodeToByteArray())
                    } catch (_: IOException) {
                        Unit
                    }
                }
            }
            .start()
        return pipe[0]
    }

    private fun authorizeOpen(uri: Uri, mode: String): FixtureProviderRoute =
        try {
            FixtureProviderBoundary.authorizeOpen(caller(), address(uri), mode)
        } catch (failure: FixtureProviderError) {
            throw FileNotFoundException(failure.code.name)
        }

    private fun authorizeDelete(uri: Uri): FixtureProviderRoute.Request =
        try {
            FixtureProviderBoundary.authorizeDelete(caller(), address(uri))
        } catch (failure: FixtureProviderError) {
            throw FileNotFoundException(failure.code.name)
        }

    private fun caller(): FixtureProviderCaller {
        val source =
            getCallingAttributionSource() ?: throw FileNotFoundException("UNVERIFIED_ATTRIBUTION")
        val packageName = getCallingPackage()
        if (source.packageName != packageName) throw FileNotFoundException("UNVERIFIED_ATTRIBUTION")
        val uid = Binder.getCallingUid()
        return FixtureProviderCaller(
            uid,
            packageName,
            requireContext().packageManager.getPackagesForUid(uid).orEmpty().toSet(),
        )
    }

    private fun address(uri: Uri) =
        FixtureProviderAddress(
            uri.scheme,
            uri.authority,
            uri.encodedPath,
            uri.query,
            uri.fragment,
            uri.userInfo,
        )

    private class UploadCallback(private val upload: FixtureRequestStaging.FixtureProxyUpload) :
        ProxyFileDescriptorCallback() {
        override fun onGetSize(): Long = 0L

        override fun onRead(offset: Long, size: Int, data: ByteArray): Int = 0

        override fun onWrite(offset: Long, size: Int, data: ByteArray): Int =
            upload.writeAt(offset, data, size)

        override fun onFsync() {
            upload.sync()
        }

        override fun onRelease() {
            upload.release()
        }
    }

    companion object {
        const val AUTHORITY = FixtureProviderBoundary.AUTHORITY
    }
}
