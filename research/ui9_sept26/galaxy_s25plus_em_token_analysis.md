*This analysis is based on the firmware for an S25+ (SM-S936B)—specifically, version EUX_S936BXXUCDZIF. This is only the beginning, and I am continuing my research.
Please note that this analysis **does not constitute a functional method for OEM unlocking**; it is simply a step forward in understanding how Samsung’s system handles EM tokens.
I used AI to summarize this information into the provided file. Since I am French, I take my research notes in French; translating and formatting a large volume of notes into English is extremely time-consuming, so I’ve relied on AI to handle the translation and formatting—I simply don't have the time to do it myself!*


# Galaxy S25+ (SM-S936B) Bootloader EM Token System — Static Analysis of Odin.efi and engmode.mbn

*Static analysis — One UI 9 / SM-S936B — November 20, 2026*

## Overview and scope

This write-up documents a static analysis of the Engineering Mode (EM) **token** subsystem found in the bootloader of a Samsung Galaxy S25+ (SM-S936B), One UI 9. Two binaries were reverse engineered in Ghidra:

- **Odin.efi** — the UEFI application that implements Download Mode, extracted from `abl.elf` with UEFITool.
- **engmode.mbn** — the TrustZone Trustlet (a Trusted Application running in the ARM Secure World, S-EL0) that Odin.efi talks to.

The EM token mechanism is the authorization layer behind Samsung's own service/repair tooling (Odin Engineering, Fenrir-class suites, factory JTAG-USB boxes). A signed token lets those tools override OEM Lock and Auto Blocker to flash custom binaries or change engineering modes on an otherwise locked device. Every token still has to be cryptographically signed by Samsung's own PKI (the "EBS Protocol CA") before the device will accept it — nothing below describes a way to forge one without that signature. This is purely a map of the internal mechanics, for anyone doing further RE work on Download Mode or on `engmode.mbn`.

## Architecture at a glance

Three layers are involved, and the token flow can be driven from any of them:

1. **Android (normal world)** — `EngineeringModeManager.makeTokenReq()` talks to `libengmode_server.so`, which issues Binder transaction 11 (`preparePayload(11)`), landing on EM_CMD_TOKEN_REQUEST (0x0b) in TrustZone.
2. **Odin.efi / Download Mode (normal world, UEFI)** — reachable even when Android is corrupted or won't boot. It exposes, over USB, both the classic bulk interface used for flashing and a virtual serial (CDC/ACM) modem interface that accepts `AT+ENGMODES=...` commands, plus a binary `Process_EMTOKEN` packet path.
3. **engmode.mbn / TrustZone (secure world, S-EL0)** — the actual Trustlet that validates, signs, encrypts and decrypts token material via an SMC/QSEE call.

Both normal-world entry points (Android and Odin.efi) ultimately reach the same TrustZone dispatcher, and both rely on the **`steady`** UFS partition plus the UFS chip's **RPMB** (Replay Protected Memory Block) for persistence — details in the sections below.

## The USB-to-TrustZone bridge: Process_EMTOKEN and BLEmMakeReq

Two strings mark the entry point of the token pipeline inside Odin.efi:

- **`Process_EMTOKEN`** (address `00075f66`) — the log identifier of the function handling Odin/Loke USB packets related to EM tokens. Following its cross-references leads straight to the command handler that receives the raw byte stream from the PC and surfaces errors such as `ODIN : TOKEN Size is too large`, `ODIN : Failed to install token`, and `ODIN : USED token`.
- **`BLEmMakeReq`** (address `00079d4c`) — the exact bootloader-side counterpart of Android's `makeTokenReq()`. Combined with the `BL_EM_CMD_GET_INFO` command (`0007a8b5`), this is where Download Mode builds and returns the token request blob (via `SendCmdEMApp` at `00079d3f`) whenever a PC tool asks for it.

## OEM Lock and Auto Blocker gating logic

Two more strings describe when a token is actually required or accepted:

- **`AUTO BLOCKER Enabled but Token exist.\n`** (`00077cf2`) — on modern One UI, this confirms that a valid EM token takes precedence over Auto Blocker: even with the feature turned on, Download Mode will proceed if a valid token is present.
- **`Non-dev device Need Token %a\n`** (`00072679`) — tracing the caller of this string leads to the exact hardware test (a fuse read / dev-vs-non-dev state check) that decides whether a token is required before a custom binary can be flashed. This is the same gate behind the `Custom Binary(%a) Blocked By OEM Lock` message.

## Token persistence and the RPMB usage counter

EM tokens are not "use forever" objects — they carry a usage counter backed by the UFS chip's RPMB:

- **`Remaining token use count is zero [%x]`** (`0007cb39`) confirms the counter's existence. It is managed through `BLWriteToken` (`00073e57`) and `BLWriteTokenLastStatus` (`0007cb22`).
- Once the counter is exhausted, the token expires and Odin.efi calls `ClearEmcToken` (`000792e3`), logging **`EM TOKEN DELETED`** (`00075ab0`).

## The AT+ENGMODES command channel

A phone in a repair shop may have a corrupted or non-booting Android system, so Samsung's official PC tools (Fenrir / Odin Engineering / factory JTAG-USB boxes) need to drive the **entire** token lifecycle from Download Mode alone. The channel that makes this possible is not the familiar Odin "bulk" flashing interface: when a Galaxy boots into Download Mode, it also exposes a virtual serial modem interface (USB CDC/ACM) that accepts standard AT commands.

A single command family, **`AT+ENGMODES=...`**, routes to `BL_EM_CMD_ESS` (`0x0c`) and covers the whole lifecycle:

- **Reading hardware info** (DID, ESI, token status) — the PC tool sends `AT+ENGMODES=<read_code>` and gets the data back.
- **Generating the pre-request** (the encrypted blob to be signed) — the PC tool sends `AT+ENGMODES=<request_code>,<modes>`; Odin.efi forwards it to `engmode.mbn`, which builds the same blob that Android's `makeTokenReq()` would produce, returned Base64/hex-encoded in the AT response.
- **Injecting the Samsung-signed token** — once Samsung's PKI servers have signed that blob, the PC tool sends it back via `AT+ENGMODES=<install_code>,<signed_token>` (or via the binary `Process_EMTOKEN` packet instead). `engmode.mbn` validates it, raises an internal flag, and Odin.efi writes it to the `steady` partition.

The exact per-command breakdown of this interface is covered in the ESS parser section below.

## Odin.efi internals: command dispatch walkthrough

Three nested functions carry one AT command from the wire into TrustZone and back.

### FUN_0006aed0 — the AT command entry point

This is the top-level switch between the different `BL_EM_CMD_*` commands. Before anything else it: replaces trailing `\r`/`\n` in the input with null bytes 4 at a time; checks the request against a 0x80000 (512 KB) ceiling, rejecting oversized input with `0xe00b0007` (`Invaild size of in`) — note for anyone reading the decompilation: Ghidra sometimes labels this constant "GostR3410-2001-TestParamSet" because an unrelated string happens to sit at the same address as `0x80000`, a label collision rather than a real algorithm reference; and writes the echo header into the output buffer (`AT+ENGMODES=` from `0x6f6cc`, the received command, then `\r\n`). It then hands off to `FUN_0006cda0`.

If `FUN_0006cda0` succeeds, it has already written its own response (e.g. `+ENGMODES=...,OK,...`) and `FUN_0006aed0` returns. If it fails, the top nibble of the error code (`uVar3 >> 0x1c == 0xe`) picks the format: a bootloader-side error becomes `+ENGMODES=<1st_char>,NG,BL,%x\r\n\r\nOK\r\n`, a command/TrustZone error becomes `+ENGMODES=<1st_char>,NG,CM,%x\r\n\r\nOK\r\n`.

### FUN_0006cda0 — the ESS bridge

This is the ESS (Enterprise Security Service) handler that glues the AT protocol to the main EM dispatcher. Instead of stack arguments it uses a dedicated global context block: `DAT_000eec00`/`DAT_000eec08` hold the input pointer and length, then it calls `FUN_0006bbc0(..., 0xc, ...)` (command `0x0c` = `BL_EM_CMD_ESS`), which relays the request to `engmode.mbn` over QSEE. On success it copies the response (`DAT_000eec10`/`DAT_000eec18`) into the USB buffer, checks the `DAT_000eec24` flag (set when TrustZone just flashed a token — logged as `Token Flash by ESS, Need update Token`), and if set, immediately re-invokes `FUN_0006bbc0(..., 0x15, ...)` to sync token state, then calls `FUN_0006a350` to update the `steady` partition and the on-screen Download Mode status. Before returning it zeroes the whole `DAT_000eec00`–`DAT_000eec24` block so no token pointer or residue survives in memory.

### FUN_0006bbc0 — building the request to TrustZone

The real dispatcher: every `BL_EM_CMD_*` id funnels through here and assembles a binary structure sent to TrustZone over two shared buffers (`DAT_000eebe8` request / `DAT_000eebf0` response): command id plus control flags, **DID** via `FUN_00069f30()` (failure → `0xe00b0001`, `Fail get did`), **CID** via `FUN_0006a280()` gated by `FUN_00014a68`, **ESI** via `FUN_000699b0()`, and the **existing token** read from the `steady` partition via `FUN_00069550()` (or from the input buffer when `DAT_000eec20 != 0`). A failure at this stage jumps to `LAB_0006c6cc` and logs `[EM]%a : Failed make ctx for em(%x)` (`00076968`).

For command `0x0c` specifically, it also copies the raw AT payload to offset `0x11615` and hardcodes the model string **`"SM-S936B"`** at offset `0x84` of the TrustZone request, which `engmode.mbn` checks against the device's actual hardware model.

The populated structure then goes to `FUN_0006b840(DAT_000eebe8, DAT_000eebf0)`, the SMC/QSEE call into `engmode.mbn` (failure logs `Failed BLEmProcessing for em`). On return, flags in the response drive what Odin.efi does next: write an updated token to `steady` via `FUN_000696a0` (`Need Update Em Token`), return an AT response string over USB, update ESI/active-mode bits or erase an expired token via `FUN_00069860` (`Remove Token`), or — for sub-command `0x1f` — set `DAT_000eec24 = 1` to trigger the `0x15` sync pass described above.

## Why Odin.efi relays through the steady partition

On recent Qualcomm platforms, a Trustlet running in S-EL0 (such as `engmode.mbn`) has no direct driver for the UFS storage's GPT partitions (`steady`, `param`, etc.). It depends on the non-secure world — Odin.efi in Download Mode, or the `em_daemon` process under Android — to act as a dumb storage relay:

1. Odin.efi reads the raw bytes of the `steady` partition and passes them to `engmode.mbn` as input (`puVar7 + 0x611`).
2. `engmode.mbn` checks the token, decrements its usage counter or updates its metadata, then encrypts and cryptographically signs the whole block before handing it back (`puVar8 + 0x1897`).
3. Odin.efi simply writes this opaque, already-sealed block back to `steady` via `FUN_000696a0` — it never sees or modifies the token's contents itself.

## Defense in depth: hardware-bound crypto plus RPMB anti-replay

Tampering with Odin.efi directly, or writing a fake token into `steady` from a rooted Android, does not work because of two independent protections:

1. **Hardware-bound authenticated encryption.** The block stored in `steady` is encrypted and authenticated (HMAC/AES-GCM) with a key derived from the SoC itself, accessible only to `tz.mbn` and `engmode.mbn`. On every subsequent boot (in `LinuxLoader.efi` or `Odin.efi`), the bootloader always hands this block back to `engmode.mbn` to decrypt and report which modes are actually active. Any tampering invalidates the authentication tag and causes an immediate rejection (logged, in the binary, as `Invalied TOKEN`).
2. **RPMB anti-replay.** The usage counter (`Remaining token use count`), the session nonce and the revocation state are stored in the UFS chip's RPMB (Replay Protected Memory Block). RPMB is protected by a symmetric key shared only between the UFS controller and TrustZone (`tz.mbn`) — Odin.efi has **no write access to RPMB at all**, so a counter or revocation flag can't simply be reset from the non-secure world.

## TrustZone side: engmode.mbn entry point and command table

### tz_app_cmd_handler (FUN_00101050)

This is the single entry point of the Trustlet, reached from either Android or Odin.efi:

- **Shared-memory validation** — `qsee_is_ns_range(param_1, param_2)` checks that the request buffer (`param_1`) and response buffer (`param_3`) sit entirely in non-secure DDR and never overlap TrustZone's protected memory.
- **Fixed buffer sizes** — the request must be exactly `0x21c7d` bytes (138,365) and the response exactly `0x20936` bytes (133,430); any other size is rejected outright.
- **Three-stage pipeline** — `FUN_00107664` (`context_request`) deserializes the input (DID, ESI, existing token, sub-command) into a 0x35300-byte internal structure; `FUN_00106af4` (`em_cmd_handler`) runs the actual command logic, after first calling `em_cmd_check_environment` and `em_cmd_pre_processing`; `FUN_001083c0` (`context_response`) re-serializes the result, the update flags meant for the `steady` partition, and any response blob into the output buffer.

### em_cmd_handler (FUN_00106af4) — environment checks

Before running any command, the Trustlet validates: **RPMB provisioning** (`FUN_00102b0c`); **fuse/security state** (`FUN_0010223c`), which reads flags such as `Enabled RPMB RSI`, `Only enabled bl`, `Only enabled ta` or `All disabled` to decide which interface (bootloader or Android TA) is allowed on this hardware revision; and, depending on the command, **existing-token validation** (`FUN_0010cfe4`, `FUN_0010caa8`) and **ESI integrity** (`em_cmd_verify_esi_core`).

### The EM_CMD_* dispatch table

| Code | Name | Handler | Role |
| --- | --- | --- | --- |
| 0x01 | EM_CMD_GET_STATUS | FUN_0010f374 | Reads general status |
| 0x02 | EM_CMD_INSTALL_TOKEN | FUN_0010f8a0 | Installs a classic binary token |
| 0x0b | EM_CMD_TOKEN_REQUEST | FUN_00116c78 | Android-side pre-request (`makeTokenReq`); 0x0b = 11, matching Android Binder transaction 11 / `preparePayload(11)` in `libengmode_server.so` |
| 0x0c | EM_CMD_ESS | FUN_00118144 | AT relay from Download Mode |
| 0x1a–0x20, 0x24 | EM_CMD_*_ESS_V1 | FUN_00118144 | All ESS sub-commands (0x1c = REQ_TOKEN_ESS_V1, 0x1f = INSTALL_TOKEN_ESS_V1, 0x1e = DELETE_TOKEN_ESS_V1) converge on the same function |

String references for the command names: `EM_CMD_TOKEN_REQUEST` (`001f916f`), `EM_CMD_ESS` (`001f907d`), `EM_CMD_REQ_TOKEN_ESS_V1` (`001f908f`), `EM_CMD_INSTALL_TOKEN_ESS_V1` (`001f90ae`), `EM_CMD_DELETE_TOKEN_ESS_V1` (`001f90d1`), `EM_CMD_GET_INFO_ESS_V1` (`001f9209`).

## The ESS AT-command parser (em_ess_command)

`em_ess_command` (`FUN_00118144`) is the full parser for everything sent after `AT+ENGMODES=`. Ghidra reads the first 4 bytes of the input as a 32-bit little-endian constant, which — decoded back to ASCII — turns out to spell the literal AT prefix:

| AT command | Internal constant | Action |
| --- | --- | --- |
| `AT+ENGMODES=0,1,<payload>` | `0x2c312c30` ("0,1,") | Generate the token pre-request (`FUN_0011a90c`, `em_ess_make_token_request`) |
| `AT+ENGMODES=0,2,<payload>` | `0x2c322c30` ("0,2,") | Install the signed token (`FUN_0011c8b8`), needs `rxivb64` and `etokenb64` fields |
| `AT+ENGMODES=0,0,<payload>` | `0x2c302c30` ("0,0,") | Build a token delete/revocation request (`FUN_0011ba28`) |
| `AT+ENGMODES=0,3,<payload>` | `0x2c332c30` ("0,3,") | Build an ESI/recovery-status request (`FUN_0011c474`) |
| `AT+ENGMODES=0,4,<payload>` | `0x2c342c30` ("0,4,") | Install the recovery response (`FUN_0011cdf8`) |
| `AT+ENGMODES=2,2,<payload>` | `0x2c322c32` ("2,2,") | Set the priority clock (`FUN_001139dc`) |

A few exact-string commands (checked with `FUN_0011e93c`, essentially `strncmp`) take no further parameters:

| AT command | Action |
| --- | --- |
| `AT+ENGMODES=0,0,3,0` | Delete the token offline, locally (`FUN_0011d0f0`) |
| `AT+ENGMODES=1,1,0` | Read current token/mode state — returns `NO_TOKEN`, `DEL,R1..R4` or `EXP,R1..R2` (`FUN_001105a0`) |
| `AT+ENGMODES=1,3,1` | Check ESS protocol version/support (`SUPPORT_ESS_V1`) |
| `AT+ENGMODES=1,2,0` | Read the priority timestamp (`FUN_0011429c`) |

### Anti-replay "keep item"

When `0,1,<payload>` runs, `engmode.mbn` generates a random nonce and an ephemeral key, then saves that state as a 0xed (237-byte) "keep item" (the same blob Odin.efi logs as `Stored keep item`). When `0,2,<payload>` later tries to install the signed token, TrustZone first checks a bit in the response (`*(byte *)(param_1 + 10) >> 6 & 1`): if no matching keep item is present in memory or on the `steady` partition, installation fails immediately with `keeping item doesn't exist` (`0xf04a0019`). This guarantees a signed token can only be installed on the exact device that issued the matching `0,1` request.

Every AT response, on success or failure, ends with the fixed 8-byte terminator `\r\n\r\nOK\r\n` (`0d 0a 0d 0a 4f 4b 0d 0a`), appended at `LAB_0011835c` and relayed unchanged by Odin.efi over the USB serial port.

## Building, encrypting and verifying the token pre-request

### Exact syntax of "0,1,..." (em_ess_parse_command_v1, FUN_0011938c)

The function first checks the protocol version (`*param_2 == 0x3130` → "01", or `0x3430` → "04") and counts the `:` separators. For a pre-request (`param_1 == 1`) it requires exactly 11 separators (12 fields):

```
AT+ENGMODES=0,1,01:<P1>:<P2>:<P3>:<P4>:<P5>:<P6>:<P7>:<P8>:<cert_len>:<cert_hex>:<sha256_hex>
```

| Field | Max size / type | Role |
| --- | --- | --- |
| Param[0] | "01" or "04" | ESS protocol version |
| Param[1] | 0x100 (256) | Session identifier / server metadata |
| Param[2] | 3 | Request type / version |
| Param[3] | 0x80 (128) | Request id / prefix |
| Param[4] | 8, numeric | Timestamp / counter |
| Param[5] | 8, numeric | Requested mode id (e.g. a bitmask for `MODE_CUST_KERNEL`) |
| Param[6] | 100 | Parameter string / mode list |
| Param[7] | 6 | Region/carrier code or flag |
| Param[8] | 5 | Sub-parameter / version |
| Param[9] | decimal | Certificate size in bytes |
| Param[10] | 0x1000 (4096), hex | Samsung server certificate, DER-encoded in hex |
| Param[11] | 0x40 (64 hex chars) | SHA-256 of everything before it (`01:<P1>:...:<cert_hex>`) |

`FUN_00103630` recomputes that SHA-256 locally and compares it to Param[11] (`FUN_0010c270`); a mismatch is rejected with `Failed to check hash` (`0xf0490016`). Everything between `01:` and `:<cert_len>:...` is saved as `mPrefixBody` (`DAT_0025f230`) for inclusion in the final signed payload.

### Assembling the plaintext (em_ess_make_token_request, FUN_0011a90c)

The function concatenates, colon-separated: `prefix_body`; protocol version ("01"/"04"); the device **IMEI** (or the placeholder `ffffffffffffff0` if it can't be read in Download Mode); the **model name** (max 16 bytes); a 32-byte random **nonce**, hex-encoded; a 32-byte random **IIN**, hex-encoded; a 3-byte status indicator; the literal platform string **"ANDROID"**; and a run of hardware/state fields (DID, chip identifiers, TSS/activation state, a hash of additional device state). If the protocol version is "04", 8 extra bytes are appended.

### Hybrid encryption (em_ess_encrypt_message, FUN_0011b174)

- Optionally verifies the server certificate's issuer Common Name equals **`EBS Protocol CA`** (`FUN_00106430`/`FUN_0011e93c`).
- Generates a random AES-256 session key and a 16-byte IV (`FUN_001015a4`).
- Encrypts the plaintext message with AES (`FUN_00105358`) → **erm** (Encrypted Request Message).
- Wraps the AES key (`FUN_00116908`) then RSA-encrypts it (`FUN_00105838`, OAEP/PKCS#1) using the server certificate's public key → **esk** (Encrypted Session Key, 256 or 512 bytes for RSA-2048/4096).
- Assembles the final AT response:

```
+ENGMODES:0,1,<version>:<esk_bin_len>:<esk_hex_len>:<esk_hex>:<erm_bin_len>:<erm_hex_len>:<erm_hex>:<sha256_esk_erm_hex>\r\n\r\nOK\r\n
```

### Certificate chain verification (em_crypto_rsa_encrypt / em_crypto_verify_cert)

`FUN_00105838` calls `FUN_00104d04` (`em_crypto_verify_cert`) before it will encrypt anything: the DER certificate from Param[10] is checked against Samsung's own embedded root CA public keys (`&DAT_001f7570`, `&DAT_001f7696`, `&DAT_001f6c78`, selected by a `root_ca_type` parameter) via `FUN_001a83a0` (`X509_verify`), and its Subject Common Name must match **`EngineeringMode`** exactly (`FUN_0011e93c`). Only once that chain-of-trust check passes does `FUN_001a1bc0` extract the RSA public key, `FUN_001759a0` validate it, and `FUN_001a4550` perform the OAEP encryption of the session key.

In practice this means Param[10] is never something generated locally: it is an X.509 certificate issued by Samsung's **EBS Protocol CA**, fetched by the official PC client (Fenrir / Odin Engineering / Steady tooling) from Samsung's own EBS server. A self-signed or arbitrary certificate fails at `FUN_00104d04` (`Failed to verify cert`) because it doesn't chain to that embedded root.

## The classic Android path: EM_CMD_TOKEN_REQUEST and its TLV format

`em_request_token` (`FUN_00116c78`) is the handler for command `0x0b`, called from Android via `EngineeringModeManager.makeTokenReq()`. Unlike the ESS/Download-Mode flow, it needs **no external certificate** — it builds a plain binary TLV (type-length-value) structure, opening with the magic header `ENGREQ0200` (`0x514552474e45` + "0200" + `0x22`), followed by these sections:

| Tag | Bytes | Contents |
| --- | --- | --- |
| TOKE | 0x54 0x4f 0x4b 0x45 | Token metadata |
| DEVI | 0x44 0x45 0x56 0x49 | Model name (`param_7`), 16-byte DID (`param_4`), 15-byte IMEI (`param_6`) |
| ISSU | 0x49 0x53 0x53 0x55 | Chip/single-id (`param_9`), operator/region code (`param_8`), 32-byte random nonce |
| MODE | 0x4d 0x4f 0x44 0x45 | List of 16-bit mode identifiers requested (`param_10`, up to 128 modes), e.g. `MODE_CUST_KERNEL` |
| VALI | 0x56 0x41 0x4c 0x49 | Requested validity duration (`param_12`, 8 bytes) |

This is the same generator that `EM_CMD_REQ_TOKEN_ESS_V1`/the `0,1,` AT command ultimately mirrors for Download Mode — the ESS path simply wraps the equivalent fields in a certificate-authenticated, AES/RSA-encrypted envelope instead of sending them as plain TLV over Binder.

## Summary and reference table

- The EM token system has two front doors — Android's `makeTokenReq()` (Binder/TLV) and Download Mode's `AT+ENGMODES=` serial channel — that both converge on the same `em_cmd_handler` dispatcher inside the `engmode.mbn` Trustlet.
- A valid token can override both OEM Lock's dev/non-dev fuse check and Auto Blocker, but every token still has to be produced and signed through Samsung's own PKI (`EBS Protocol CA`); the pre-request/install exchange is authenticated end-to-end with a certificate chain check, hybrid AES/RSA encryption, a SHA-256 integrity check on the AT payload itself, and a per-request "keep item" that pins a signed token to the device that requested it.
- Odin.efi never touches the `steady` partition's token bytes directly — it is a relay for an opaque, TrustZone-sealed blob — and has no write access at all to the UFS RPMB, which is where the replay-protected usage counter and revocation state actually live.
- Token usage is metered: once the RPMB-backed counter hits zero, the token is cleared (`ClearEmcToken` / `EM TOKEN DELETED`).

### Reference: Odin.efi (bootloader side)

| Address / name | Role |
| --- | --- |
| `Process_EMTOKEN` (00075f66) | USB Odin packet handler for EM tokens |
| `BLEmMakeReq` (00079d4c) | Bootloader analog of Android's `makeTokenReq()` |
| `BL_EM_CMD_GET_INFO` (0007a8b5) / `SendCmdEMApp` (00079d3f) | Builds and returns the token-request blob over USB |
| `AUTO BLOCKER Enabled but Token exist.` (00077cf2) | A valid token overrides Auto Blocker |
| `Non-dev device Need Token %a` (00072679) | Dev/non-dev fuse gate before custom-binary flashing |
| `Remaining token use count is zero [%x]` (0007cb39) | RPMB-backed usage counter exhausted |
| `BLWriteToken` (00073e57) / `BLWriteTokenLastStatus` (0007cb22) | Writes token / last-write status |
| `ClearEmcToken` (000792e3) / `EM TOKEN DELETED` (00075ab0) | Token wipe on expiry |
| `FUN_0006aed0` | Top-level AT command entry point / dispatcher |
| `FUN_0006cda0` | ESS bridge: AT protocol ↔ EM command dispatcher |
| `FUN_0006bbc0` | Central EM command dispatcher; builds the TrustZone request |
| `FUN_0006a350` | Updates `steady` partition + Download Mode on-screen status |
| `Failed make ctx for em(%x)` (00076968) | Context-build failure (DID/CID/ESI/token read) |
| `FUN_00069f30` / `FUN_0006a280` / `FUN_000699b0` / `FUN_00069550` | Read DID / CID / ESI / existing token |
| `FUN_0006b840` | SMC/QSEE call into `engmode.mbn` |
| `FUN_000696a0` / `FUN_00069af0` / `FUN_00069860` | Write updated token / update ESI / remove expired token |

### Reference: engmode.mbn (TrustZone side)

| Address / name | Role |
| --- | --- |
| `FUN_00101050` (tz_app_cmd_handler) | Trustlet entry point; validates shared-memory buffers and sizes |
| `FUN_00107664` / `FUN_001083c0` | Deserialize request / serialize response (context_request / context_response) |
| `FUN_00106af4` (em_cmd_handler) | Main command dispatcher; runs environment checks, then the EM_CMD_* table |
| `FUN_00102b0c` / `FUN_0010223c` | RPMB provisioning check / fuse-security-state check |
| `FUN_0010cfe4`, `FUN_0010caa8`, `em_cmd_verify_esi_core` | Existing-token and ESI integrity validation |
| `FUN_0010f374` (0x01), `FUN_0010f8a0` (0x02) | EM_CMD_GET_STATUS, EM_CMD_INSTALL_TOKEN |
| `FUN_00116c78` (0x0b) | EM_CMD_TOKEN_REQUEST — Android `makeTokenReq`, ENGREQ0200 TLV builder |
| `FUN_00118144` (0x0c, 0x1a–0x20, 0x24) | em_ess_command — AT relay + all ESS_V1 sub-commands |
| `FUN_0011938c` (em_ess_parse_command_v1) | Parses the "0,1,..." field list, checks the local SHA-256 (`FUN_00103630`/`FUN_0010c270`) |
| `FUN_0011a90c` (em_ess_make_token_request) | Assembles the colon-separated plaintext pre-request |
| `FUN_0011b174` (em_ess_encrypt_message) | Hybrid AES session-key + RSA wrap encryption |
| `FUN_00105838` (em_crypto_rsa_encrypt) / `FUN_00104d04` (em_crypto_verify_cert) | RSA-OAEP encrypt / X.509 chain verification against Samsung's embedded root CA |
| `FUN_0011c8b8`, `FUN_0011ba28`, `FUN_0011c474`, `FUN_0011cdf8`, `FUN_001139dc`, `FUN_0011d0f0`, `FUN_001105a0`, `FUN_0011429c` | Install token / build delete request / build ESI request / install recovery response / set priority clock / delete token offline / read token state / read priority timestamp |
| `EM_CMD_TOKEN_REQUEST` (001f916f), `EM_CMD_ESS` (001f907d), `EM_CMD_REQ_TOKEN_ESS_V1` (001f908f), `EM_CMD_INSTALL_TOKEN_ESS_V1` (001f90ae), `EM_CMD_DELETE_TOKEN_ESS_V1` (001f90d1), `EM_CMD_GET_INFO_ESS_V1` (001f9209) | Command-name strings tied to the dispatch table above |

*All addresses are as found in this specific SM-S936B / One UI 9 bootloader/TrustZone image; they will shift between firmware builds, so treat them as a starting point for cross-referencing rather than fixed offsets.*
