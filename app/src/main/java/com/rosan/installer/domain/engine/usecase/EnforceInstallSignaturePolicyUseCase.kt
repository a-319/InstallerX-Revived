// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.domain.engine.usecase

import android.content.Context
import android.content.pm.PackageManager
import com.rosan.installer.data.engine.signature.InstalledPackageSignatureReader
import com.rosan.installer.data.engine.signature.PendingApkSignatureAnalyzer
import com.rosan.installer.data.policy.ManagedInstallPolicyProvider
import com.rosan.installer.data.policy.ZipSignatureVerifier
import com.rosan.installer.domain.engine.exception.InstallException
import com.rosan.installer.domain.engine.model.error.InstallErrorType
import com.rosan.installer.domain.engine.model.install.sourcePath
import com.rosan.installer.domain.engine.model.packageinfo.AppEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

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
class EnforceInstallSignaturePolicyUseCase(
    private val context: Context,
    private val pendingApkSignatureAnalyzer: PendingApkSignatureAnalyzer,
    private val installedPackageSignatureReader: InstalledPackageSignatureReader
) {

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

        // The installed app's signing certificates, for the genuine-update comparison.
        val installedCertHashes =
            if (installed) resolveInstalledCertHashes(packageName) else emptySet()

        // Rules 1 + 3: every selected base APK must either be signed with an authorized
        // certificate, or be signed with the same certificate as the installed app.
        // An unresolvable signature never qualifies.
        val allBasesAuthorized = baseEntities.all { base ->
            val hashes = resolveApkCertHashes(base)
            hashes.isNotEmpty() &&
                    hashes.all { it in allowedHashes || it in installedCertHashes }
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
     * Signer certificate SHA-256 hashes of the already installed app, used for the
     * genuine-update comparison. Empty when the signature cannot be read.
     */
    private fun resolveInstalledCertHashes(packageName: String): Set<String> {
        val info = installedPackageSignatureReader.read(packageName) ?: return emptySet()
        return info.signerSha256Set.mapTo(mutableSetOf()) { it.lowercase() }
    }

    /**
     * Signer certificate SHA-256 hashes of an incoming base APK. Reuses the analysis
     * produced while parsing when available, otherwise runs apksig over the entity's
     * data (staging non-file sources into the cache dir). Returns an empty set when the
     * APK signature cannot be verified, so an unverifiable APK never satisfies the policy.
     */
    private fun resolveApkCertHashes(base: AppEntity.BaseEntity): Set<String> {
        val info = base.signatureInfo
            ?: pendingApkSignatureAnalyzer.analyze(base.data, context.cacheDir.absolutePath)
        if (info == null || !info.verified) return emptySet()
        return info.signerSha256Set.mapTo(mutableSetOf()) { it.lowercase() }
    }
}
