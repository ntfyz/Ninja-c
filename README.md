# Ninja-c localhost loader rebuild

This repository rebuilds the ARM64 `loader.framework` from the supplied
`Ninja_8BallPool_v56.27.0.ipa`, replaces the original remote authentication with a
localhost key/HWID service, and packages an unsigned IPA in GitHub Actions.

The application binary and `ninja.framework` stay intact. The replacement loader keeps
the ABI used by the Ninja login screen:

- stable 64-character device ID stored in the iOS Keychain;
- login against a configurable HTTP endpoint (localhost by default);
- session generation, expiry, validation, invalidation callback, and logout;
- saved credentials for automatic session restoration;
- local SQLite commands to create/delete/enable/disable keys and set/clear HWIDs.

## Local key server

Create a key. When `--password` is omitted, enter the generated key in both the Username
and Password fields in the Ninja login form.

```bash
python server/auth_server.py create-key --days 30
python server/auth_server.py serve --host 127.0.0.1 --port 8880
```

Manage the key database:

```bash
python server/auth_server.py list-keys
python server/auth_server.py clear-hwid KEY
python server/auth_server.py set-hwid KEY 64_HEX_CHARACTER_HWID
python server/auth_server.py disable-key KEY
python server/auth_server.py enable-key KEY
python server/auth_server.py delete-key KEY
```

`127.0.0.1` is the iPhone itself. If the server runs on another machine, run the GitHub
workflow manually and set `auth_url` to that machine's reachable LAN/VPN URL, for example
`http://192.168.1.20:8880/ninja_ios_v2/api/v1/auth/login`.

## Build the unsigned IPA

The source IPA is split into Git-friendly parts under `input/`. A push to `main` starts
the workflow. It:

1. verifies and joins the IPA parts;
2. cross-compiles `ios/loader.mm` for iPhoneOS ARM64;
3. replaces `Payload/pool.app/Frameworks/loader.framework`;
4. removes stale code-signature directories and enables local HTTP in `Info.plist`;
5. uploads `Ninja_8BallPool_v56.27.0_localhost_unsigned.ipa` as the
   `Ninja-localhost-unsigned-ipa` artifact.

No signing certificate or provisioning profile is used. Sign/install the resulting IPA
with the signing setup already present on the target device.

## Verification and analysis

Run server tests with:

```bash
python -m unittest discover -s server -p "test_*.py"
```

For repeatable RVA disassembly, install `requirements-analysis.txt` and use:

```bash
python tools/analyze_macho.py PATH_TO_MACHO --rva 0x437c
```

See [`analysis/RVA_MAP.md`](analysis/RVA_MAP.md) for the confirmed symbols and protocol
findings.

## Supplied-image limitation

The supplied IPA has no downloaded autoplay WASM payload. It contains WAMR plus only the
eight-byte WASM header constants, while the real module is fetched after the old remote
login. The replacement loader therefore exports stable no-op module functions so the
native UI remains usable, but module-only autoplay planning stays disabled. Login,
session, logout, device ID, and the other native Ninja features remain available.
