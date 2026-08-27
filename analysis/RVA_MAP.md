# ARM64 RVA map and authentication findings

Source image: `Ninja_8BallPool_v56.27.0.ipa`  
Bundle: `Payload/pool.app`  
Bundle identifier: `com.ninja.ios.engine`  
Version: `56.27.0` (`5299`)  
Minimum iOS: `13.0`

All three custom binaries are thin ARM64 Mach-O dylibs with `cryptid=0`, so their RVA is
also the file offset throughout `__TEXT`.

| Image | RVA | Confirmed symbol / role |
|---|---:|---|
| `ninja.framework/ninja` | `0x4997C` | `DrawLogin()` |
| `ninja.framework/ninja` | `0x47188` | `LoginWantsKeyboard` |
| `ninja.framework/ninja` | `0x47228` | `LoginFeedBackspace` |
| `ninja.framework/ninja` | `0x472F4` | `LoginFeedChar` |
| `ninja.framework/ninja` | `0xD3740` | `getIOSClipboard` |
| `ninja.framework/ninja` | `0x2EDE4` | `Login(std::string, std::string)` |
| `ninja.framework/ninja` | `0xA8A04` | login worker created by `DrawLogin()` |
| `ninja.framework/ninja` | `0xAF7C0` | `ninja_security_login(...)` wrapper |
| `loader.framework/loader` | `0x845C` | `ninja_loader_login` C ABI wrapper |
| `loader.framework/loader` | `0x437C` | original `ninja_security_login(...)` implementation |
| `loader.framework/loader` | `0x16F60` | `gdl_saved_login_load` |
| `loader.framework/loader` | `0x1768C` | `gdl_saved_login_store` |
| `loader.framework/loader` | `0x8700` | `ninja_loader_session_valid` |
| `loader.framework/loader` | `0x8748` | `ninja_loader_logout` |

## Original flow

`ninja.framework` does not link directly to `loader.framework`. Its lazy `Backend()`
resolver uses `dlsym(RTLD_DEFAULT, ...)` for:

- `ninja_loader_login`
- `ninja_loader_set_invalidation_callback`
- `ninja_loader_device_id`
- `ninja_loader_session_valid`
- `ninja_loader_logout`

The original login routine builds this JSON body:

```json
{"username":"...","password":"...","device_id":"64-hex-hwid"}
```

It initializes the old API client for `sultandx.com:443` with two pinned SPKI hashes,
establishes an X25519/HMAC protected session, and posts to:

```text
/ninja_ios_v2/api/v1/auth/login
```

A successful response must contain `ok=true`, `scope="authenticated"`, `expires_at`, and
`remaining_seconds`. The old loader then requests `/ninja_ios_v2/api/v1/module/fetch`,
validates/decrypts a delivery envelope, installs the downloaded WASM module, starts an
integrity watcher, and only then returns a non-zero login generation.

## Login result ABI and minimal patch

The C result buffer used at `ninja_loader_login` is 96 bytes:

| Offset | Size | Meaning |
|---:|---:|---|
| `0x00` | 4 | success flag |
| `0x04` | 4 | reserved/padding |
| `0x08` | 8 | expiry epoch |
| `0x10` | 8 | remaining seconds |
| `0x18` | 8 | non-zero session generation |
| `0x20` | 64 | NUL-terminated status/error code |

Ninja copies the three 64-bit fields, stores the generation in `g_active_generation`,
calls `ninja_loader_session_valid`, and accepts the result only when the generation still
matches. The minimal patch preserves the complete original loader and changes only:

- `0x845C`: zero the result, accept exactly `1` / `1`, and initialize coherent offline
  generation/expiry state;
- `0x8700`: return a valid session.
- `0xD6D4`: neutralize the guard-failure callback that otherwise invalidates the offline
  session, performs a retired-server heartbeat, and logs out.
- `0xEC10`: stop the recurring 1 ms Appdome thread-kill watchdog while retaining the
  initial memory bypass, syscall hooks, early scans, and detection-state watcher.

This retains the loader's original platform startup and Objective-C compatibility hooks.
Replacing the complete loader removed those behaviors and caused the runtime protection
event `REF 6960` (`MethodSwizzlingDetected`) before the Ninja login screen initialized.

## Autoplay payload check

`loader.framework` contains WAMR and the constants `\0asm\x01\0\0\0` at file offsets
`0x566EA` and `0x566F2`, but no complete embedded WASM module. No `.wasm` or downloaded
module file exists anywhere in the app bundle. The minimal login patch therefore does
not claim to reconstruct the missing planner payload.
