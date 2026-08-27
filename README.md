# Ninja-c minimal offline login patch

This repository applies a minimal ARM64 patch to the original `loader.framework` from
`Ninja_8BallPool_v56.27.0.ipa` and packages an unsigned IPA in GitHub Actions.

The application binary, `ninja.framework`, original loader startup, Objective-C hooks,
framework metadata, and all other IPA files stay intact. Only the authentication path
and its offline guard callback are changed:

- `ninja_loader_login` accepts exactly Username `1` and Password `1`, then creates a
  coherent offline generation and expiry;
- `ninja_loader_session_valid` returns a valid session after login;
- the loader guard still loads Ninja normally, but its obsolete server-heartbeat failure
  callback is neutralized for the offline session;
- the original Appdome compatibility startup remains active.

This avoids localhost networking and preserves the compatibility behavior in the
original loader. Sign the output with ESign, then enter `1` in both login fields.

## Build the unsigned IPA

The source IPA is split into Git-friendly parts under `input/`. A push to `main` starts
the workflow. It:

1. verifies and joins the IPA parts;
2. verifies the SHA-256 of the original loader;
3. patches login RVA `0x845c`, session RVA `0x8700`, and guard-failure callback RVA
   `0xd6d4`;
4. replaces only `Payload/pool.app/Frameworks/loader.framework/loader`;
5. verifies the patch and uploads
   `Ninja_8BallPool_v56.27.0_stable_offline_1-1_unsigned.ipa`.

No certificate or provisioning profile is embedded. Sign/install the output using the
signing setup already present on the target device.

## Local verification

```bash
python tools/ipa_parts.py join \
  input/Ninja_8BallPool_v56.27.0.ipa.parts.json \
  build/Ninja_8BallPool_v56.27.0.ipa
# Extract Payload/pool.app/Frameworks/loader.framework/loader to build/source/loader.
python tools/patch_loader.py build/source/loader build/patched/loader
python tools/patch_ipa_minimal.py \
  build/Ninja_8BallPool_v56.27.0.ipa \
  --loader-binary build/patched/loader \
  --output dist/Ninja_8BallPool_v56.27.0_stable_offline_1-1_unsigned.ipa
```

The optional server and replacement-loader source remain in the repository for protocol
testing, but the release workflow does not use them.

For repeatable RVA disassembly, install `requirements-analysis.txt` and use:

```bash
python tools/analyze_macho.py PATH_TO_MACHO --rva 0x437c
```

See [`analysis/RVA_MAP.md`](analysis/RVA_MAP.md) for the confirmed symbols and protocol
findings.

## Supplied-image limitation

The supplied IPA has no downloaded autoplay WASM payload. It contains WAMR plus only the
eight-byte WASM header constants; the real module was fetched after remote login. The
login patch does not recreate that module, so functionality implemented only by the
downloaded module remains absent.
