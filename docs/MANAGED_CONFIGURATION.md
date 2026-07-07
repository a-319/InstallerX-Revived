# Managed Configuration: Install Signature Policy

InstallerX Revived supports an enterprise install restriction delivered through
[Android Enterprise managed configurations](https://developer.android.com/work/managed-configurations)
(app restrictions). It lets an MDM/EMM administrator lock the installer down so
that each device only installs software approved for that device.

## Restriction key

| Key | Type | Default |
|-----|------|---------|
| `allowed_install_signatures` | `string` | empty (policy disabled) |

The value is a list of **SHA-256 hashes of signing certificates**, separated by
commas, semicolons or whitespace. Both plain hex
(`3f2a…`) and colon-separated (`3F:2A:…`) formats are accepted; case does not
matter. Because the value is a plain string, every device (or device group) can
receive a different set of authorized hashes from the MDM console.

## Behavior

When `allowed_install_signatures` contains at least one valid hash, the
installer only permits a package when **one** of the following holds:

1. **Authorized APK signature** — the base APK is signed with a certificate
   whose SHA-256 is in the list.
2. **Authorized signed container** — the package (any signer) was opened from a
   ZIP archive whose JAR signature verifies against a certificate in the list.
   Every content entry of the ZIP must be covered by the signature; tampered or
   partially signed archives are rejected. Magisk/KernelSU module ZIPs are only
   allowed through this rule.
3. **Update to an installed app** — the package name is already installed on
   the device (Android itself additionally enforces that updates match the
   installed app's signature).

Anything else fails with an "Installation blocked by managed policy" error.

When the restriction is empty or absent (e.g. on unmanaged devices), no
restriction is applied and the installer behaves normally.

The restriction is re-read on every installation, so policy changes pushed by
the MDM take effect immediately without restarting the app.

## Getting the certificate hash

For an APK signing certificate:

```sh
apksigner verify --print-certs app.apk
# "Signer #1 certificate SHA-256 digest: ..."
```

or from a keystore:

```sh
keytool -list -v -keystore release.jks -alias mykey
# "SHA256: AA:BB:..."
```

## Signing a ZIP container

To deliver arbitrary (third-party signed) APKs, pack them into a ZIP and sign
it with the authorized key using `jarsigner`:

```sh
jarsigner -keystore release.jks -digestalg SHA-256 -sigalg SHA256withRSA bundle.zip mykey
```

The installer will accept any APK contained in such a ZIP as long as the ZIP
signature verifies against an authorized certificate.

## Testing without an MDM

You can push restrictions locally with
[TestDPC](https://github.com/googlesamples/android-testdpc), or on a debug
build via:

```sh
adb shell dpm set-application-restrictions ...
```
