# Galaxy S25+ (SM-S936B) Bootloader EM Token System — Part 2: linuxloader.efi Static Analysis

*Static analysis — One UI 9 / SM-S936B — November 21, 2026*

*This is Part 2 of the static-analysis series on the SM-S936B / One UI 9 Engineering Mode token system, continuing directly from the previous write-up covering Odin.efi and engmode.mbn. This part covers the third binary involved: `linuxloader.efi`.*

## Overview

`linuxloader.efi` is the UEFI stage that actually boots Android (as opposed to `Odin.efi`, which only handles Download Mode). Searching its strings for the token-related identifiers used elsewhere (`ENGRSS`, `CUST_KERNEL`, `engmode`) turns up nothing directly — and that absence is itself informative: it confirms the same privilege separation seen in the rest of the chain.

- **`linuxloader.efi` never parses the `ENGRSS0002` token container itself.** That job belongs exclusively to the `engmode.mbn` Trustlet running in TrustZone (Secure EL1/S-EL0), which alone holds the Samsung root public keys and hardware access to RPMB.
- **`linuxloader.efi`'s own job is narrower**: it reads the `steady` partition into RAM and forwards it, and it consumes status — it asks a secure-world service (via SMC) whether a given mode or override is currently active, and acts on the answer. It never decides on its own whether a token is valid.

This split is exactly what the rest of this doc traces in detail: the decision function that consumes TrustZone's answer (`CheckAndSetEMC`), the in-RAM permission cache it reads from, and the broker function that actually talks to TrustZone.

## CheckAndSetEMC and the "has cust tk but not bootloader" string

The clearest entry point into this logic is a log string: **`[%a]: has cust tk but not bootloader \n`** (`0x000c9c55`, `tk` = token). Its cross-references lead directly to **`FUN_000a5070`**, which names itself in its own log output as **`CheckAndSetEMC`** ("Engineering Mode Check") at `0x000a5178`.

`CheckAndSetEMC` takes a pointer to an image-verification context (`param_9`) and decides whether a standard signature failure on a partition (`*param_9 != 0` or `param_9[1] != 0`) can be waived because a valid Engineering Mode token covers it.

- **Return 0** (`LAB_000a50b8` / `LAB_000a50bc`): boot is allowed — either the binary is legitimately signed, or a valid EM token covers this partition.
- **Return 1** (`LAB_000a51b8`): boot is blocked — no valid override exists, and the bootloader will show `Custom Binary Blocked By OEM Lock` / FRP / R/L.

The exact string above is produced inside one specific branch of that logic (detailed next): the device holds a valid custom-kernel token (`has cust tk`), but the request is for a partition outside that token's scope (`not bootloader`) — so the override does not apply and the boot is blocked.

## CheckAndSetEMC: full decision logic by image type

The branch taken depends on the image type being verified, read from `iVar1 = param_9[0xe]`:

### iVar1 == 0 — unknown / uncovered binary

Logs `"[%a]: binary type known \n"` and immediately returns 1 (blocked). No override path exists for a type the bootloader doesn't recognize.

### iVar1 == 6 — Knox-related images / test containers

Calls `FUN_000ba230(4)` to check for a Knox test token (mode bit 4). If absent (`== 0`), returns 1 (blocked). This is the **only** branch that ever consults bit 4.

### iVar1 == 4 — kernel/system images (boot, init_boot, vendor_boot, etc.)

This is the richest branch, checked in order:

1. **`FUN_000b9ec0(...)`** — first checks whether the image itself carries an embedded development/test signature. If so (`== 1`), it's allowed immediately (return 0), no token needed at all.
2. **`FUN_000ba230(3)`** — checks for an active Bootloader-unlock token (mode bit 3). If one is active (`!= 0`), it then checks `if (param_9[1] == 0xd)`:
   - If `param_9[1] == 0xd` (this is a boot/kernel image), allow (return 0).
   - Otherwise (a different partition, e.g. `recovery` or `vbmeta`, which this token doesn't cover), log **`"[%a]: has cust tk but not bootloader \n"`** and block (return 1). This is the exact string traced above: the device holds a custom-kernel token, but not a full bootloader unlock, and the current partition needs the latter.
3. **`FUN_000ba230(0)`** — checks `MODE_CUST_KERNEL` (mode bit 0). If active (`!= 0`), calls `FUN_000ba6c0(..., 0, 1, ...)` to consume/apply the token and sets the global `DAT_001978bc = 1` — which later drives the on-screen `[BLDP] %a : kernel_build_type = Custom` message and increments `custom_count`.
   - If `FUN_000ba6c0` fails (`!= 0`), it calls `FUN_000ba400` (error handling / cleanup) and blocks (return 1).

## The steady partition driver inside linuxloader.efi

Every cross-reference to the raw string `"steady"` (`0x000dc8e9`) lands in the same narrow address range, `0x000b94cc`–`0x000ba900` — a self-contained module for reading, writing and consulting the `steady` partition and the TrustZone link:

| Address / name | Role |
| --- | --- |
| `FUN_000b94cc`–`FUN_000b9d5c` | Low-level read/write/erase of the `steady` partition on UFS, plus relaying data to TrustZone/SPU via SMC/QSEE |
| `FUN_000b9ec0` | Alternative signature check on the image buffer loaded in RAM (the dev/test-signature check used in `CheckAndSetEMC`) |
| `FUN_000ba230(mode_type)` | Token-state query: asks TrustZone (or the in-RAM cache) whether a given mode is authorized (0 = `MODE_CUST_KERNEL`, 3 = Bootloader, 4 = Knox Test) |
| `FUN_000ba400` | Error handler when a token consumption fails (`get token state fail %x`) |
| `FUN_000ba6c0(..., mode, action)` | Token activation/consumption: asks TrustZone to apply the authorization (decrementing the usage counter in MODB on the `steady` partition when `max_uses > 0`) |
| `FUN_000ba7c8` & `FUN_000ba900` | `steady` maintenance functions (likely reset/purge on Factory Reset or an Odin flash) |

## The in-RAM permission bitmask: DAT_001a3d20

`linuxloader.efi` does not re-read the `steady` partition on every check. Instead it keeps a bitmask in RAM at the global address **`DAT_001a3d20`**, where each bit represents one EM mode currently authorized on the device.

### Reading a bit — FUN_000ba230(mode_id)

```c
return (uint)(*(ulonglong *)(&DAT_001a3d20 + (param_1 >> 6 & 0x3ffffff) * 2) >> (param_1 & 0x3f)) & 1;
```

- `param_1 >> 6` divides `mode_id` by 64, selecting the right 64-bit word in the `DAT_001a3d20` array.
- `param_1 & 0x3f` isolates the exact bit (0–63) for that mode within the word.
- This is a plain RAM read: 1 if the mode is active, 0 otherwise.

### Consuming a bit — FUN_000ba6c0

It first checks that same bit in `DAT_001a3d20`. If it is 0, it returns immediately with error `0xe00a0003` and logs `"[EM]%a : Mode not Exist(%x) get modes\n"` (the `[EM]` prefix confirms the whole `0x000b9...`–`0x000bc...` block is the bootloader's Engineering Mode client). If the bit is 1, it calls `FUN_000bc040((short)param_9, ...)` — the direct interface function that sends the request to the secure service (TrustZone/SPU) to actually execute the action tied to that mode.

### Where the mask gets filled

The write-side cross-references to `DAT_001a3d20` lead to the initialization function that reads the `steady` partition at boot, sends it to `engmode.mbn` for cryptographic validation, and writes the resulting mask of valid modes into `DAT_001a3d20` (full flow in the TrustZone-broker section below).

## MODE_CUST_KERNEL vs. the Knox Test Token — not a master key

Bit 4 of `DAT_001a3d20` ("Knox Test Token") is not a passe-partout that bypasses every security check on the phone. Its scope is strictly fenced by the image-type parameter `iVar1 = param_9[0xe]` inside `CheckAndSetEMC`:

| `param_9[0xe]` value | Image type checked | EM mode queried in `DAT_001a3d20` | Actual scope |
| --- | --- | --- | --- |
| 4 | Kernel/system partitions (`boot`, `init_boot`, `vendor_boot`, etc.) | Bit 0 (`MODE_CUST_KERNEL`) or bit 3 (Bootloader) | Authorizes booting a custom kernel only, if signed or covered by the token |
| 6 | Knox-specific test binaries/containers | Bit 4 (Knox Test Token) | Authorizes loading a Knox test module/binary only (used by Samsung's Knox QA/validation teams) |

Two things keep it from "unlocking everything":

1. **Partitioning by image type.** In `CheckAndSetEMC`, bit 4 (`FUN_000ba230(4)`) is only ever tested when the bootloader is verifying an image classified as type 6. Flashing a modified `boot.img` (type 4) never takes the `iVar1 == 6` branch at all — a token with only bit 4 set is simply irrelevant to the kernel check.
2. **Same cryptographic requirements.** Bit 4 is just one more mode ID (`0x0004`) encoded in the same `ENGRSS0002` token format, subject to exactly the same TrustZone checks as every other mode: binding to the hardware DID, the `VALI` validity window, and RSA-4096 (`INTE`) signature verification by Samsung's authority.

Activating either mode still flips the device into the Custom state (`kernel_build_type = Custom`, `custom_count` incremented) and remains subject to the usual hardware locks (FAP/FRP, KG, Knox e-fuse).

## FUN_000bb0e0: the TrustZone broker

`FUN_000bc040` is a thin request marshaller: it stores the requested mode id in `DAT_001a3dcc` and the action (e.g. 1 = activate/consume at boot) in `DAT_001a3dd0`, then calls **`FUN_000bb0e0(..., 1, ...)`** — the actual client that talks to `engmode.mbn`. This runs in three phases.

### 1. Building the request buffer (puVar7 = DAT_001a3d88)

Before calling TrustZone, the function gathers hardware identifiers and the token itself into one shared buffer:

- **DID** — `FUN_000b9e10()` reads the 16-byte Device ID into `puVar7 + 0x25` (failure → `0xe00b0001`, `Fail get did`).
- **CID** — if the DID matches a particular pattern (`DAT_000ddd06`), `FUN_000ba160()` reads an 8-byte Chip ID into `puVar7 + 0x574` (failure → `0xe00b000c`, `Fail get cid`).
- **ESI** — `FUN_000b9890()` reads Engineering Security Info (anti-replay counters/session metadata) into `puVar7 + 0x1f07d` (failure → `0xe00b0002`, `Fail get esi`).
- **Token** — if a token is already cached in RAM (`DAT_001a3dc0 != 0`), it's copied from `DAT_001a3da0` into `puVar7 + 0x611`; otherwise `FUN_000b9430()` reads it straight from the `steady` partition.
- **Command-specific fields** (`param_9`): `== 1` (boot-time verify/consume) writes the requested mode to `puVar7 + 0x2ac` and the action flag to `puVar7 + 0x2aa`; `== 0xc` (new-token injection via Odin/Download Mode) copies the new token to `puVar7 + 0x11615`, the model string `"SM-S936B"` to `puVar7 + 0x84`, and 0xed bytes of persistent state (`DAT_001a3d98`) to `puVar7 + 0x42a`.

### 2. The call into TrustZone (FUN_000bad60)

```c
uVar21 = FUN_000bad60(DAT_001a3d88, DAT_001a3d90);
```

`FUN_000bad60` is the SMC/QSEE wrapper that switches the processor into the Secure World and passes the request buffer (`DAT_001a3d88`) and response buffer (`DAT_001a3d90`) to `engmode.mbn`. Everything — validating the `ENGRSS0002` TLV structure, the DID/model match, the `VALI` date window, the MODB usage quotas, and the RSA-4096 `INTE` signature — happens inside this call, in the secure world.

### 3. Executing TrustZone's response (BLEmActionRsp)

If `uVar12 == 0` (valid token), `linuxloader.efi` reads a set of flags from the response buffer (`puVar8 = DAT_001a3d90`) and acts on them:

| Response flag | Associated log | Action taken by linuxloader.efi |
| --- | --- | --- |
| `*puVar2 >> 4 & 1` | `Need Update Em Token` | `FUN_000b9580(puVar8 + 0x1897, 0x11000)` — rewrite `steady` on UFS (e.g. after the usage counter was decremented, or on a new flash) |
| `*puVar2 & 1` | (pointer update) | Updates `DAT_001a3db0`/`DAT_001a3db8` — the response/pre-request buffer to return to the USB host |
| `*puVar2 >> 2 & 1` | `Need Update Esi info` | `FUN_000b99d0(puVar8 + 0x297, 0x2c00)` — update the ESI security state |
| `puVar8[0x11] >> 1 & 1` | `Stored keep item` | Saves 0xed bytes of persistent context into `DAT_001a3d98` |
| `puVar8[0x11] >> 5 & 1` | `Need Update Bits` | Copies 0x20 bytes (256 bits) from `puVar8 + 0x8b` directly into `DAT_001a3d20` — this is where the authorized-modes mask (including `MODE_CUST_KERNEL` and the Knox Test mode) actually gets populated |
| `puVar8[0x11] >> 8 & 1` | `Need Clear ESI` | `FUN_000b9b90()` — erases ESI metadata |
| `puVar8[0x11] >> 3 & 1` | `Remove Token` | `FUN_000b9740()` — erases the token from `steady` (expired single-use token) |
| `puVar8[9] >> 3` or `>> 4` | `write LTS INS` / `DEL` | `FUN_000b9d40()` — write or delete an LTS (Long Term Storage / RPMB-backed) marker |

The picture that emerges: `linuxloader.efi` itself never validates a token's signature and never computes the `DAT_001a3d20` mask — `engmode.mbn` decides everything during the `FUN_000bad60` call, and `linuxloader.efi` only applies the resulting orders (write the mask, rewrite or erase `steady`).

## steady partition layout, caching, and token erasure

### FUN_000b9580 — writing the token to flash

This function reveals the exact internal layout of the `steady` partition:

```c
iVar3 = FUN_000b5f70((byte *)"steady", 0x5000, param_1, (ulonglong)param_2);
```

- The `ENGRSS0002` container is **not** stored at offset 0 of `steady` — it lives at offset **`0x5000`** (20,480 bytes / 20 KB) inside the partition. The first 20 KB (`0x0000`–`0x4FFF`) are reserved for other persistent Samsung structures (notably ESI data and other bootloader/system state flags). This is why a raw `steady.bin` dump has a header/offset before the `ENGRSS0002` magic.
- The maximum token slot size is **`0x11000`** bytes (69,632 / 68 KB), guarded by `if (param_2 < 0x11001)` — generous enough for multiple X.509 certificates and extended MODB/GRDB sections.
- On a successful UFS write, `linuxloader.efi` also maintains an in-RAM cache at **`DAT_001a3d00`** (0x11000 bytes, zeroed via `FUN_00005b94` then filled via `FUN_00005e70`), so later steps in the same boot cycle read the token straight from RAM instead of re-reading UFS.

### Full offset map of the steady partition

| Function | Offset in `steady` | Max size | Role |
| --- | --- | --- | --- |
| `FUN_000b9890` / `FUN_000b99d0` | Earlier region (≈ `0x0000`–`0x4FFF`) | `0x2c00` (11 KB) | Read/write ESI data (anti-replay counters and session metadata) |
| `FUN_000b9430` / `FUN_000b9580` | `0x5000` | `0x11000` (68 KB) | Read/write the `ENGRSS0002` token container |
| `FUN_000b9740` | `0x5000` | `0x11000` | Erase the token slot (`Remove Token`) on expiry |

### FUN_000b9740 — token deletion/revocation

Called when TrustZone's response sets the `Remove Token` flag (`puVar8[0x11] >> 3 & 1`), e.g. once a single-use or temporary token hits `max_uses`:

1. Allocates a zeroed 0x11000-byte buffer (`FUN_000bc170()`).
2. Overwrites the `steady` slot at offset `0x5000` with those zeros via `FUN_000b9580(puVar4, 0x11000)`, also wiping the RAM cache `DAT_001a3d00`.
3. On success, draws the red (`0xff0000`) **`EM TOKEN DELETED`** banner on screen (`FUN_000305f0`) and frees the temporary buffer (`FUN_000bc2b0()`).

## Full chain summary

Putting `CheckAndSetEMC`, `FUN_000bb0e0` and `FUN_000b9580`/`FUN_000b9740` together, the complete boot-time cycle looks like this:

```
[UFS partition "steady"]
  ├── offset 0x0000 : ESI (Engineering Security Info — counters/state, 0x2c00 bytes)
  └── offset 0x5000 : ENGRSS0002 token container (max size 0x11000 / 68 KB)
           │
           ▼  read at boot via FUN_000b9430
[linuxloader.efi : FUN_000bb0e0]
  ├── collects DID (FUN_000b9e10), CID (FUN_000ba160), ESI (FUN_000b9890)
  ├── sends context + token to TrustZone over SMC/QSEE (FUN_000bad60)
  │
  ▼  secure-world execution inside engmode.mbn
[TrustZone : engmode.mbn]
  ├── verifies the TLV format, DID/model match, VALI date window, MODB quotas,
  │   and the RSA-4096 INTE signature
  ├── decrements usage counters where required
  └── returns the 256-bit permission mask + action flags (BLEmActionRsp)
           │
           ▼  back in linuxloader.efi
[linuxloader.efi applies the orders]
  ├── copies the 256-bit mask into DAT_001a3d20 ("Need Update Bits")
  ├── rewrites steady at 0x5000 if the counter changed ("Need Update Em Token" → FUN_000b9580)
  ├── erases steady at 0x5000 if expired ("Remove Token" → FUN_000b9740 + "EM TOKEN DELETED")
  └── CheckAndSetEMC (FUN_000a5070) reads DAT_001a3d20 (bit 0 = MODE_CUST_KERNEL, bit 3 = Bootloader, bit 4 = Knox Test)
```

The takeaway is the same separation of concerns seen on the Odin.efi side (Part 1): `linuxloader.efi` is purely an executor — it never validates a token's signature and never computes the permission mask itself. `engmode.mbn` in TrustZone decides everything during the SMC call, and the bootloader only carries out the orders it's handed back: update the bitmask, rewrite or erase `steady`.

## Reference: linuxloader.efi functions and strings

| Address / name | Role |
| --- | --- |
| `"has cust tk but not bootloader"` (0x000c9c55) | Device holds a custom-kernel token but not a bootloader unlock — logged when `CheckAndSetEMC` blocks a non-kernel partition |
| `"[SPU]Don't find steady partition"` (0x000c6626) | SPU (Secure Processing Unit) can't locate `steady` |
| `"steady"` (0x000dc8e9) | Raw GPT partition name string, used to locate `steady` on UFS |
| `"[%a] Custom binary(%a) by verifystatus(%d)"` (0x000d4e04) | AVB (Android Verified Boot) decision-point log when an image fails standard verification |
| `CUSTOM_VBMETA` (0x000d72c5) | Custom-vbmeta state marker consulted at the AVB decision point |
| OEM Lock / FRP Lock / R-L messages (0x000d07c8, 0x000cc021, 0x000cd0bc) | Lock-state strings shown when no override applies |
| `FUN_000a5070` (CheckAndSetEMC, self-named at 0x000a5178) | Core EMC decision function; waives a signature failure if a valid token covers the partition |
| `FUN_000b9ec0` | Checks for an embedded dev/test signature on the image buffer |
| `FUN_000ba230(mode_type)` | Reads one bit of the `DAT_001a3d20` permission mask (0 = MODE_CUST_KERNEL, 3 = Bootloader, 4 = Knox Test) |
| `FUN_000ba400` | Error handler on token-consumption failure (`get token state fail %x`) |
| `FUN_000ba6c0` | Consumes/applies a token mode; calls `FUN_000bc040` to reach TrustZone |
| `FUN_000ba7c8` / `FUN_000ba900` | `steady` maintenance (reset/purge on factory reset or Odin flash) |
| `FUN_000bc040` | Request marshaller: stores mode id (`DAT_001a3dcc`) and action (`DAT_001a3dd0`), calls `FUN_000bb0e0` |
| `FUN_000bb0e0` | Main TrustZone broker: builds the request buffer, calls `FUN_000bad60`, applies `BLEmActionRsp` flags |
| `FUN_000b9e10` / `FUN_000ba160` / `FUN_000b9890` / `FUN_000b9430` | Read DID / CID / ESI / existing token from `steady` |
| `FUN_000bad60` | SMC/QSEE call into `engmode.mbn` |
| `FUN_000b9580` | Writes the token container to `steady` at offset `0x5000` (max `0x11000` bytes) and refreshes the RAM cache `DAT_001a3d00` |
| `FUN_000b9740` | Erases the token slot (`Remove Token`), shows the red `EM TOKEN DELETED` banner |
| `FUN_000b99d0` / `FUN_000b9b90` / `FUN_000b9d40` | Update / clear ESI data; write or delete an LTS (RPMB-backed) marker |
| `DAT_001a3d20` | In-RAM 256-bit bitmask of currently authorized EM modes |
| `DAT_001a3d00` | In-RAM cache (0x11000 bytes) of the current `steady` token blob |
| `DAT_001a3d88` / `DAT_001a3d90` | Shared request / response buffers for the `FUN_000bad60` SMC call |

*As with Part 1, all addresses are specific to this SM-S936B / One UI 9 `abl.elf` image and will shift between firmware builds — use them as a starting point for cross-referencing, not as fixed offsets.*
