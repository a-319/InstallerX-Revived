package com.rosan.installer.data.privileged.util

import android.content.pm.PackageManager
import android.os.Build
import com.rosan.dhizuku.api.Dhizuku
import com.rosan.dhizuku.api.DhizukuRequestPermissionListener
import com.rosan.installer.data.privileged.exception.DhizukuNotWorkException
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first

suspend fun <T> requireDhizukuPermissionGranted(action: suspend () -> T): T {
    // Dhizuku (and Dhizuku-API 2.5.4+) requires Android 8.0+; the library's
    // minSdk is force-overridden in the manifest, so never reach it below O.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O)
        throw DhizukuNotWorkException(UnsupportedOperationException("Dhizuku requires Android 8.0+"))
    callbackFlow {
        Dhizuku.init()
        if (Dhizuku.isPermissionGranted()) send(Unit)
        else {
            Dhizuku.requestPermission(object : DhizukuRequestPermissionListener() {
                override fun onRequestPermission(grantResult: Int) {
                    if (grantResult == PackageManager.PERMISSION_GRANTED) trySend(Unit)
                    else close(Exception("dhizuku permission denied"))
                }
            })
        }
        awaitClose()
    }.catch {
        throw DhizukuNotWorkException(it)
    }.first()
    return action()
}