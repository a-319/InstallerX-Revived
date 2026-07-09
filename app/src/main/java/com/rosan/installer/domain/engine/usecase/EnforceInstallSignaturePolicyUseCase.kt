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
 *  3. It is a genuine update to an application that is already installed on the
 *     device: the incoming base APK must be signed with the same certificate as the
 *     installed app. A same-package APK with a mismatched signer is NOT an update —
 *     letting it through would fail in PackageManager and surface the
 *     "uninstall and retry" suggestion, uninstalling the legitimate app.
 *
 * The policy is re-evaluated on every install attempt against the current device
 * state, so retry flows (e.g. after an uninstall) cannot bypass it.
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

        val installed = isPackageInstalled(packageName)
        val baseEntities = entities.filterIsInstance<AppEntity.BaseEntity>()

        // Rule 3 (splits-only case): adding splits/dex-metadata to an installed app is
        // always a genuine update; PackageManager enforces they match the installed
        // base signature.
        if (baseEntities.isEmpty()) {
            if (installed) {
                Timber.d("Policy: $packageName allowed as splits-only update to installed app")
            }
            return installed ||
                    areContainersAuthorized(entities, allowedHashes, containerCache)
        }

        // The installed app's signing certificate, for the genuine-update comparison.
        val installedCertHash = if (installed) {
            SignatureUtils.getInstalledAppSignatureHash(context, packageName)?.lowercase()
        } else null

        // Rules 1 + 3: every selected base APK must either be signed with an authorized
        // certificate, or be signed with the same certificate as the installed app.
        // An unresolvable signature never qualifies.
        val allBasesAuthorized = baseEntities.all { base ->
            val hash = (base.signatureHash ?: resolveApkCertHash(base.data))?.lowercase()
            hash != null && (hash in allowedHashes || (installedCertHash != null && hash == installedCertHash))
        }
        if (allBasesAuthorized) {
            Timber.d("Policy: $packageName allowed by authorized or installed-matching APK signature")
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
