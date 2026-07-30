// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2023-2026 iamr0s, InstallerX Revived contributors
package com.rosan.installer.framework.privileged.core.execution.authorization

import android.content.pm.PackageManager
import com.rosan.dhizuku.api.Dhizuku
import com.rosan.dhizuku.api.DhizukuRequestPermissionListener
import com.rosan.installer.domain.privileged.exception.PrivilegedException
import com.rosan.installer.domain.privileged.model.PrivilegedErrorType
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import timber.log.Timber

/**
 * Number of attempts to establish the Dhizuku connection before giving up.
 *
 * [Dhizuku.init] talks to the Dhizuku manager app through a ContentProvider and
 * returns a boolean success flag. On a "cold" manager process the very first
 * call frequently returns false (the binder has not been handed back yet), which
 * is exactly why the first install attempt used to fail with
 * "can't connect to Dhizuku" while a manual second attempt succeeded. Retrying a
 * few times within the same attempt makes the connection reliable on the first try.
 */
private const val DHIZUKU_INIT_MAX_ATTEMPTS = 5

/** Delay between [Dhizuku.init] retries. */
private const val DHIZUKU_INIT_RETRY_DELAY_MS = 200L

/**
 * Ensures a live Dhizuku connection is established, retrying the (synchronous)
 * [Dhizuku.init] handshake because it can fail on the first cold attempt.
 *
 * @return true once [Dhizuku.init] reports success, false if every attempt failed.
 */
private suspend fun ensureDhizukuInitialized(): Boolean {
    repeat(DHIZUKU_INIT_MAX_ATTEMPTS) { attempt ->
        val connected = runCatching { Dhizuku.init() }
            .onFailure { Timber.tag("Dhizuku").w(it, "Dhizuku.init() threw on attempt ${attempt + 1}") }
            .getOrDefault(false)
        if (connected) return true
        Timber.tag("Dhizuku")
            .d("Dhizuku.init() not ready on attempt ${attempt + 1}/$DHIZUKU_INIT_MAX_ATTEMPTS, retrying")
        if (attempt < DHIZUKU_INIT_MAX_ATTEMPTS - 1) delay(DHIZUKU_INIT_RETRY_DELAY_MS)
    }
    return false
}

suspend fun <T> requireDhizukuPermissionGranted(action: suspend () -> T): T {
    callbackFlow {
        if (!ensureDhizukuInitialized()) {
            close(Exception("dhizuku connection not established"))
            return@callbackFlow
        }
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
        throw PrivilegedException(
            errorType = PrivilegedErrorType.DHIZUKU_NOT_WORK,
            message = "Dhizuku not work",
            cause = it
        )
    }.first()
    return action()
}
