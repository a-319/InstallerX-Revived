// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.data.policy

import timber.log.Timber
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.jar.JarFile

/**
 * Verifies the JAR-style signature (as produced by jarsigner / apksigner v1) of an
 * arbitrary ZIP archive and reports the SHA-256 hashes of the certificates that
 * signed EVERY content entry in it.
 *
 * A container is only considered signed by a certificate if that certificate covers
 * all non-signature entries and the cryptographic verification of each entry succeeds
 * (tampered entries raise SecurityException while streaming and fail the whole file).
 */
object ZipSignatureVerifier {

    private const val BUFFER_SIZE = 64 * 1024

    /**
     * Returns the SHA-256 hashes (lowercase hex) of the certificates that signed all
     * content entries of the ZIP at [path], or an empty set when the archive is
     * unsigned, partially signed, or fails verification.
     */
    fun getFullCoverageSignerCertHashes(path: String): Set<String> {
        val file = File(path)
        if (!file.isFile) return emptySet()

        return try {
            JarFile(file, true).use { jar ->
                val contentEntries = jar.entries().toList()
                    .filter { !it.isDirectory && !isSignatureRelated(it.name) }
                if (contentEntries.isEmpty()) return emptySet()

                var commonSigners: MutableSet<String>? = null
                val buffer = ByteArray(BUFFER_SIZE)

                for (entry in contentEntries) {
                    // Entries must be fully read for their signature to be verified;
                    // a corrupted entry throws SecurityException here.
                    jar.getInputStream(entry).use { input ->
                        @Suppress("ControlFlowWithEmptyBody")
                        while (input.read(buffer) != -1) {
                        }
                    }

                    val signers = entry.codeSigners
                    if (signers.isNullOrEmpty()) {
                        Timber.w("Unsigned entry '${entry.name}' in $path, rejecting container signature")
                        return emptySet()
                    }

                    val entryCertHashes = signers.asSequence()
                        .flatMap { it.signerCertPath.certificates.asSequence() }
                        .filterIsInstance<X509Certificate>()
                        .map { sha256Hex(it.encoded) }
                        .toMutableSet()

                    if (commonSigners == null) {
                        commonSigners = entryCertHashes
                    } else {
                        commonSigners.retainAll(entryCertHashes)
                    }
                    if (commonSigners.isEmpty()) return emptySet()
                }

                commonSigners ?: emptySet()
            }
        } catch (e: Exception) {
            // SecurityException (tampered), ZipException (not a zip), IO errors, ...
            Timber.w(e, "ZIP signature verification failed for $path")
            emptySet()
        }
    }

    private fun isSignatureRelated(name: String): Boolean {
        val upper = name.uppercase()
        if (!upper.startsWith("META-INF/")) return false
        return upper == "META-INF/MANIFEST.MF" ||
                upper.endsWith(".SF") ||
                upper.endsWith(".RSA") ||
                upper.endsWith(".DSA") ||
                upper.endsWith(".EC")
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
