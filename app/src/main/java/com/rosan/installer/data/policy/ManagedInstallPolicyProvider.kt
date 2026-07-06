// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.data.policy

import android.content.Context
import android.content.RestrictionsManager
import timber.log.Timber

/**
 * Reads the managed install signature policy delivered through Android Enterprise
 * managed configurations (app restrictions).
 *
 * The restriction [RESTRICTION_ALLOWED_SIGNATURES] carries the SHA-256 hashes of the
 * signing certificates that are authorized on this device. When at least one valid
 * hash is configured, the installer refuses any package that is not covered by the
 * policy (see EnforceInstallSignaturePolicyUseCase). When the restriction is absent
 * or empty, no restriction is applied.
 */
object ManagedInstallPolicyProvider {

    const val RESTRICTION_ALLOWED_SIGNATURES = "allowed_install_signatures"

    private val HEX_SHA256 = Regex("^[0-9a-f]{64}$")
    private val TOKEN_SEPARATORS = Regex("[,;\\s]+")

    /**
     * Returns the set of authorized signing certificate SHA-256 hashes
     * (lowercase hex, no separators), or an empty set when the device is
     * not managed / the policy is not configured.
     */
    fun getAllowedSignatureHashes(context: Context): Set<String> {
        val restrictionsManager =
            context.getSystemService(Context.RESTRICTIONS_SERVICE) as? RestrictionsManager
                ?: return emptySet()

        val restrictions = try {
            restrictionsManager.applicationRestrictions
        } catch (e: Exception) {
            Timber.e(e, "Failed to read managed application restrictions")
            return emptySet()
        } ?: return emptySet()

        val rawTokens = buildList {
            restrictions.getString(RESTRICTION_ALLOWED_SIGNATURES)
                ?.let { addAll(it.split(TOKEN_SEPARATORS)) }
            // Some EMMs deliver list values as a string array even for string keys.
            runCatching { restrictions.getStringArray(RESTRICTION_ALLOWED_SIGNATURES) }
                .getOrNull()?.let { addAll(it) }
        }

        val hashes = rawTokens.mapNotNull { normalizeSha256(it) }.toSet()
        if (rawTokens.any { it.isNotBlank() } && hashes.isEmpty()) {
            Timber.w("Managed install policy is configured but contains no valid SHA-256 hashes")
        }
        return hashes
    }

    /**
     * Normalizes a user-supplied SHA-256 value ("AA:BB:..." or plain hex) to
     * lowercase hex without separators. Returns null for invalid values.
     */
    fun normalizeSha256(raw: String): String? {
        val cleaned = raw.trim().replace(":", "").lowercase()
        return cleaned.takeIf { HEX_SHA256.matches(it) }
    }
}
