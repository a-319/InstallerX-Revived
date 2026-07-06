// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.domain.engine.usecase

import android.content.Context
import android.content.pm.PackageManager
import com.rosan.installer.data.engine.parser.SignatureUtils
import com.rosan.installer.data.policy.ManagedInstallPolicyProvider
import com.rosan.installer.data.policy.ZipSignatureVerifier
import com.rosan.installer.domain.engine.exception.InstallException
import com.rosan.installer.domain.engine.model.AppEntity
import com.rosan.installer.domain.engine.model.DataEntity
import com.rosan.installer.domain.engine.model.InstallErrorType
import com.rosan.installer.domain.engine.model.sourcePath
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import java.util.UUID

/**
 * Enforces the managed install signature policy (delivered via managed configurations).
 *
 * When the device policy defines at least one authorized signing certificate SHA-256,
 * a package may only be installed when one of the following holds:
 *  1. Its base APK is signed with an authorized certificate.
 *  2. It comes from a ZIP container whose JAR signature is fully verified against an
 *     authorized certificate (regardless of the APK's own signer).
 *  3. It is an update to an application that is already installed on the device.
 *
 * When no policy is configured (unmanaged device / empty restriction), installation
 * is unrestricted.
 */
class EnforceInstallSignaturePolicyUseCase(private val context: Context) {

    suspend operator fun invoke(apps: List<AppEntity>) = withContext(Dispatchers.IO) {
        val allowedHashes = ManagedInstallPolicyProvider.getAllowedSignatureHashes(context)
        if (allowedHashes.isEmpty()) return@withContext

        Timber.d("Managed install policy active with ${allowedHashes.size} authorized certificate(s)")

        // Container verification is expensive; verify each distinct file only once per call.
        val containerCache = mutableMapOf<String, Boolean>()

        apps.groupBy { it.packageName }.forEach { (packageName, entities) ->
            if (!isGroupAuthorized(packageName, entities, allowedHashes, containerCache)) {
                Timber.w("Managed install policy rejected package: $packageName")
                throw InstallException(
                    InstallErrorType.SIGNATURE_POLICY_VIOLATION,
                    "Package $packageName is not authorized by the managed install signature policy"
                )
            }
        }
    }

    private fun isGroupAuthorized(
        packageName: String,
        entities: List<AppEntity>,
        allowedHashes: Set<String>,
        containerCache: MutableMap<String, Boolean>
    ): Boolean {
        // Magisk/KernelSU modules are not APK-signed and never "installed" as packages:
        // they are only allowed when flashed from an authorized signed ZIP (rule 2).
        if (entities.any { it is AppEntity.ModuleEntity }) {
            return areContainersAuthorized(entities, allowedHashes, containerCache)
        }

        // Rule 3: update of an app that is already installed on this device.
        if (isPackageInstalled(packageName)) {
            Timber.d("Policy: $packageName allowed as update to installed app")
            return true
        }

        // Rule 1: base APK signed with an authorized certificate.
        val baseEntity = entities.filterIsInstance<AppEntity.BaseEntity>().firstOrNull()
        val apkCertHash = baseEntity?.signatureHash ?: baseEntity?.let { resolveApkCertHash(it.data) }
        if (apkCertHash != null && apkCertHash.lowercase() in allowedHashes) {
            Timber.d("Policy: $packageName allowed by authorized APK signature")
            return true
        }

        // Rule 2: delivered inside a ZIP container signed with an authorized certificate.
        return areContainersAuthorized(entities, allowedHashes, containerCache)
    }

    private fun areContainersAuthorized(
        entities: List<AppEntity>,
        allowedHashes: Set<String>,
        containerCache: MutableMap<String, Boolean>
    ): Boolean {
        val containerPaths = entities.mapNotNull { it.data.sourcePath() }.distinct()
        if (containerPaths.isEmpty()) return false

        val authorized = containerPaths.all { path ->
            containerCache.getOrPut(path) {
                ZipSignatureVerifier.getFullCoverageSignerCertHashes(path)
                    .any { it in allowedHashes }
            }
        }
        if (authorized) {
            Timber.d("Policy: allowed by authorized signed container(s): $containerPaths")
        }
        return authorized
    }

    private fun isPackageInstalled(packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    /**
     * Computes the signing certificate SHA-256 of an APK whose parsed entity carries
     * no precomputed hash. Non-file sources are staged to the cache dir first, since
     * PackageManager can only parse real file paths.
     */
    private fun resolveApkCertHash(data: DataEntity): String? {
        if (data is DataEntity.FileEntity && File(data.path).isFile) {
            return SignatureUtils.getApkSignatureHash(context, data.path)
        }

        val tempFile = File(context.cacheDir, "sig_check_${UUID.randomUUID()}.apk")
        return try {
            val input = data.getInputStreamWhileNotEmpty() ?: return null
            input.use { stream ->
                tempFile.outputStream().use { output -> stream.copyTo(output) }
            }
            SignatureUtils.getApkSignatureHash(context, tempFile.absolutePath)
        } catch (e: Exception) {
            Timber.e(e, "Failed to stage APK for signature check")
            null
        } finally {
            tempFile.delete()
        }
    }
}
