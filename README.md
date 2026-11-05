# File signature policy

`app.stokerhq.file-signature`: a [Stoker](https://github.com/StokerHQ) hook plugin for an integration that replaces a
signed library in a program's folder with Stoker's own. A program that checks that library's Authenticode signature
would refuse the replacement. This plugin answers those checks from the original file. It changes no file on disk.

## What it does

- Detours `CryptQueryObject` in the process it runs in (only in `process`, when that is set). A file query for the
  file named `match` queries `replace` in the same folder instead - the original, kept beside the replacement - and
  returns that answer, with the caller's output parameters as they are.
- With `trustPolicy`, `WinVerifyTrust` is answered too: `forward` (the default) verifies as usual,
  `accept-matched` reports success for a file check of `match`, `accept-all` reports success for every check in the
  process.
- File names compare as final names only, case-insensitively: a directory or a suffix never matches.

Windows only (x86 and x64).

## Options

| Option | | |
|---|---|---|
| `match` | required | The file name the program checks. |
| `replace` | required | The file in the same folder to query instead. |
| `trustPolicy` | optional | `forward`, `accept-matched` or `accept-all`. |
| `logging` | optional | `quiet`, or `changes` to log every redirected query and accepted check. |
| `process` | optional | Only act inside this executable. |

## Tests

`tests/signature_core.cpp` checks file name matching and the policy parser; CI runs it for x86 and x64.
## Releases

A release is tagged `v<version>`, the version the manifest in the source declares; CI refuses a tag that differs. The
release's assets are built by CI from the tagged commit (`file-signature-windows-x86.dll`, `file-signature-windows-x64.dll`) and are what the StokerHQ plugin registry
(`app.stokerhq.file-signature` in [StokerHQ/plugins](https://github.com/StokerHQ/plugins)) lists by SHA-256 and BLAKE3, signed by the
StokerHQ publisher key.

## Building

```powershell
./build.ps1
```

Needs Visual Studio with the C++ workload. The SDK is the release `stoker-plugin.yaml` pins, fetched once and checked by
SHA-256; `STOKER_PLUGIN_SDK` names a local SDK folder or zip instead.

## Licence

AGPL-3.0-or-later (`LICENSE`).