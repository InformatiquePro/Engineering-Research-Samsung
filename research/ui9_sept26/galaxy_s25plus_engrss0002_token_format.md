# Galaxy S25+ (SM-S936B) Bootloader EM Token System — Part 3: ENGRSS0002 Token Container Format

*Static analysis — One UI 9 / SM-S936B — November 22, 2026*

*This is Part 3 of the static-analysis series on the SM-S936B / One UI 9 Engineering Mode token system, continuing from the Odin.efi/engmode.mbn write-up (Part 1) and the linuxloader.efi write-up (Part 2). Where Parts 1 and 2 traced how the bootloader and TrustZone move an EM token around and decide whether to honor it, this part documents the token itself: the exact binary layout of the `ENGRSS0002` container that both sides agree on.*

## Overview and scope

This deep dive into the token format itself was made possible by analysis of real, valid `ENGRSS0002` tokens that grant `MODE_CUST_KERNEL` — the mode that authorizes flashing and booting a custom kernel — captured from Galaxy S25 and Galaxy S26 (Ultra) devices, alongside one older token issued through what looks like an internal engineering tool rather than the commercial issuance path. The analysis covers `steady`-partition captures and AT+ENGMODES exchanges, spanning at least two issuance paths: tokens issued through Samsung's `BinaryLicense` B2B portal, and that older token (project name `DASEUL`).

> **A note on what's reproduced here.** The source dumps contain real device identifiers (DID, IMEI), an internal Samsung server IP address, and internal operator account names tied to the people who approved specific tickets. This is a deliberate redaction, not an oversight: none of that is reproduced below — every device identifier, IP and account name in this write-up is a clearly marked placeholder. Only the container's structure, the field layout, and the cryptographic mechanism are documented.

`ENGRSS0002` is a hierarchical TLV (Tag-Length-Value) format, little-endian throughout, built from three structural levels: a main header plus an 8-slot section-offset table, eight named 4-byte-tag sections (`TOKE`, `DEVI`, `ISSU`, `MODE`, `VALI`, `MODB`, `GRDB`, `INTE`), and sub-fields nested inside each section. The format is deliberately extensible — new sub-tags can be added without breaking older parsers, since every section and sub-field declares its own size.

## Main header and section offset table (0x000–0x02D)

| Offset | Size | Content | Meaning |
|---|---|---|---|
| 0x000 | 10 bytes | Magic | ASCII `ENGRSS0002` |
| 0x00A | 4 bytes | uint32 LE | `0x0000002E` (46 bytes) — the header's own size, not the whole container's. The total file size isn't stored anywhere; it's derived dynamically from the end of the last section (`offset_INTE + 12 + size_INTE`) |
| 0x00E | 4 bytes | uint32 LE | Offset of `TOKE` |
| 0x012 | 4 bytes | uint32 LE | Offset of `DEVI` |
| 0x016 | 4 bytes | uint32 LE | Offset of `ISSU` |
| 0x01A | 4 bytes | uint32 LE | Offset of `MODE` |
| 0x01E | 4 bytes | uint32 LE | Offset of `VALI` |
| 0x022 | 4 bytes | uint32 LE | Offset of `INTE` |
| 0x026 | 4 bytes | uint32 LE | Offset of `MODB` |
| 0x02A | 4 bytes | uint32 LE | Offset of `GRDB` |

Before trusting anything inside the file, `engmode.mbn` checks that every one of these eight pointers lands exactly on the 4-byte tag it claims to.

One subtlety worth flagging: the offset table's *slot* order (`TOKE, DEVI, ISSU, MODE, VALI, INTE, MODB, GRDB`) is not the same as the sections' *physical* on-disk order. Walking the actual file byte-for-byte, the sections appear as `TOKE → DEVI → ISSU → MODE → VALI → MODB → GRDB → INTE` — `INTE`, the cryptographic seal, is always placed last physically (since it has to sign everything before it), even though its pointer sits earlier in the table.

## Section header format and the chaining rule

Every section begins with the same 12-byte descriptor:

```
[4 bytes: ASCII tag][4 bytes: data size, uint32 LE][4 bytes: element count, uint32 LE]
```

Sections chain together with a simple formula — `next_offset = current_offset + 12 + data_size` — which is also how `engmode.mbn` derives the end of the file (the end of `INTE`) without a stored total-size field.

Inside a section, two different sub-field conventions are used depending on which section it is: `TOKE`/`DEVI`/`ISSU`/`VALI`/`MODE` use a simple `[uint16 ID][uint16 Length][Value]` sub-TLV (covered next — `MODE`'s entries are just very small); `MODB`/`GRDB` use fixed-size records with a nested sub-TLV only for their rule attributes; `INTE` just holds two large sub-TLV blobs.

## TOKE — token identity

| Sub-tag | Size | Meaning |
|---|---|---|
| 0x0001 | 16 bytes | Unique transaction ID |
| 0x0002 | 2 bytes | Type/version flag, `0x0001` |
| 0x0003 | 2 bytes | State indicator, `0x0001` |
| 0x0005 | 1 byte | Protocol revision, `0x04` (absent on the DASEUL sample) |

`TOKE` carries no device binding of its own — that's `DEVI`'s job. It exists purely to give the token a unique identity that TrustZone can key its own live state against (see the `MODB` usage-tracking discussion below).

## DEVI — the hardware anchor

| Sub-tag | Size | Meaning |
|---|---|---|
| 0x0001 | 8 bytes | ASCII model string |
| 0x0002 | 16 bytes | ASCII hex — **DID** (the only mandatory sub-tag) |
| 0x0003 | 15 bytes | ASCII IMEI1 |

*(Real DID/IMEI values are redacted throughout this write-up and replaced with placeholders.)*

The older DASEUL sample's `DEVI` section carries **only** the DID sub-tag — no model string, no IMEI — which confirms that DID alone is the mandatory binding; the model and IMEI checks are additional constraints layered on top specifically for B2B-portal-issued tokens.

## ISSU — issuance traceability

| Sub-tag | Size | Meaning |
|---|---|---|
| 0x0001 | varies (ASCII) | Operator account on B2B tokens, or the literal string `DASEUL` on the internal sample |
| 0x1001 | 13 bytes | License category, e.g. `BinaryLicense` |
| 0x1002 | varies | Internal EBS server IP (B2B tokens only) |
| 0x0003 | 32 bytes | Session nonce (DASEUL sample only) |

*(Operator account names and the internal server IP are redacted throughout this write-up and replaced with placeholders.)*

The presence or absence of sub-tag `0x0003` distinguishes two different issuance paths: a **static** path through Samsung's `BinaryLicense` B2B portal (no nonce — the token is simply generated and handed over), versus an **interactive** path built around the `ENGREQ0200`/`AT+ENGMODES=0,1,...` pre-request flow documented in Part 1 (where a session nonce ties the final token back to a specific live request).

## VALI — validity window

| Sub-tag | Size | Meaning |
|---|---|---|
| 0x0001 | 8 bytes (ASCII) | Start date |
| 0x0002 | 8 bytes (ASCII) | End date — `99999999` means no expiry |

In practice, a token's real effective lifetime is governed by the `MODB` usage quota, not by this calendar window — a token with `99999999` as its end date still stops working the moment its quota is exhausted.

## MODE and MODB — the permission catalog and its quotas

### MODE — sub-TLV list of authorized mode IDs

`MODE` uses the same simple sub-field convention as `TOKE`/`DEVI`/`ISSU`/`VALI` (`[uint16 ID][uint16 Length][Value]`), not a flat array — its entries are just small. On the S25 token analyzed, the section's data size is `0x08` (8 bytes) over 2 elements: two 4-byte sub-TLV entries, sub-tag 1 (length 2) with value `0x0005`, and sub-tag 2 (length 2) with value `0x0003` — i.e. `MODE_DEBUG_CP` and `MODE_CUST_KERNEL`.

### MODB — one detailed record per mode

Each `MODB` entry is a fixed-layout record:

```
[uint16 mode ID][uint16 record size][32 bytes name][128 bytes description][sub-TLV: rule attributes]
```

| Sub-tag (inside the rule-attribute sub-TLV) | Meaning |
|---|---|
| 0x0001 | Group ID (links to `GRDB`) |
| 0x0002 | Persistence / factory-reset flag |
| 0x0003 | Usage-counter verification policy |
| 0x0004 | `max_uses` — `0x0000000A` (10) for `MODE_CUST_KERNEL`, `0x0000270F` (9999) for `MODE_DEBUG_CP` |
| 0x0005 | Consumed-use counter so far (always `0x00` at issuance) |
| 0x0006 | Revocation/state flag |
| 0x0007 | Optional Base64-encoded approval note (present on the S25 sample, absent on the S26 Ultra sample) |

The S25 sample's `MODB` record carries 7 sub-tags totaling `0x6e` bytes (including the optional `0x0007` approval note, which decodes to a short Korean-language approval comment); the S26 Ultra sample's record has only 6 sub-tags and `0x22` bytes, omitting `0x0007` entirely.

### How usage tracking actually works: immutable token vs. RPMB state

Because `INTE` signs every byte from `0x000` through the end of `GRDB`, and `engmode.mbn` only ever embeds Samsung's **public** Root CA key — never a private signing key — TrustZone can never modify a single byte of `MODB` (including sub-tags `0x0004`/`0x0005`) inside the `ENGRSS0002` container and then re-sign `INTE`. Doing so would immediately invalidate the RSA-4096 signature, and the very next boot's SHA-256 check over `token[0x000 : off_INTE]` would fail outright.

- **Inside the signed blob (`steady` partition): values frozen at issuance.** `0x0004` (`max_uses`) and `0x0005` (the initial state/counter, always `0x00` at issuance) remain strictly immutable for the token's entire lifetime — they're exactly what the Samsung server signed, and nothing on-device can touch them.
- **In RPMB (Replay Protected Memory Block): the real, live counter.** `engmode.mbn` tracks the actual consumed-use count separately, in RPMB, indexed by the token's unique transaction ID (`TOKE` sub-tag `0x0001`). RPMB is hardware-protected against replay by a Qualcomm SoC HMAC key, and only TrustZone can write to it.
- **On each boot or flash that consumes a mode**, TrustZone first verifies the untouched `ENGRSS0002` signature in `steady`, then reads and increments the RPMB-backed counter for that transaction ID. Once the live count reaches `max_uses` — or a previously-exhausted `TOKE` transaction ID is seen again — TrustZone signals `linuxloader.efi`/`Odin.efi` to wipe the token from `steady` (`Need Update Em Token` → `Remove Token` / `EM TOKEN DELETED`, as covered in Part 2).

This is exactly why replaying an old raw dump of `steady.bin` doesn't reset the quota: the RSA signature on the replayed blob is still perfectly valid, but RPMB still remembers that transaction ID as exhausted, and blocks it regardless.

## GRDB — functional groups

| Group ID | Name | Linked mode |
|---|---|---|
| 0x0000 | `Binary Flashing` | `MODE_CUST_KERNEL` |
| 0x0002 | `Debugging FT` | `MODE_DEBUG_CP` |

`GRDB` records are fixed-size and byte-identical across every sample analyzed — they describe the functional group a mode belongs to, not anything issuance-specific.

## INTE — the cryptographic seal

`INTE` is always the physically-last section, since it has to sign everything before it:

```
49 4e 54 45            : magic "INTE"
<uint32 LE>             : section size (0x0826 = 2,086 bytes)
02 00 00 00             : element count (2)
```

| Sub-tag | Size | Meaning |
|---|---|---|
| 0x0001 | 0x200 (512 bytes) | RSA-4096 signature over the SHA-256 digest of `token[0x000]` through the end of `GRDB` |
| 0x0002 | 0x61E (1,566 bytes) | Signer's X.509 certificate, DER-encoded |

That checks out exactly against the section's own declared data size: two 4-byte sub-TLV headers (`[uint16 ID][uint16 Length]`, one per sub-tag) plus the 512-byte signature and 1,566-byte certificate values — `4 + 512 + 4 + 1,566 = 2,086` bytes — is precisely `0x0826`, the size `INTE`'s own 12-byte section header declares.

### A padding quirk worth flagging for anyone verifying this signature

Sub-tag `0x0001` is not a standard `sha256WithRSAEncryption` signature the way the X.509 certificate in `0x0002` is. The certificate's own signature uses the normal ASN.1 `DigestInfo` encapsulation; the token's `INTE` signature over `token[0x000 : off_INTE]` does not — it's raw PKCS#1 v1.5 padding with no ASN.1 `DigestInfo` header at all: `00 01 [0xFF × 477 bytes] 00 [32 raw SHA-256 bytes]`. Verifying it with OpenSSL or Python's `cryptography` in their default/standard RSA-PKCS1-with-DigestInfo mode will fail even against a genuine, validly signed token — the digest has to be compared against the last 32 bytes of the decrypted padding directly, bypassing the library's usual `DigestInfo` parsing.

The older DASEUL-issued sample's `INTE` section is smaller and starts earlier in the file (fewer `MODB`/`GRDB` entries to sign) and its signature sub-tag is 256 bytes rather than 512 — consistent with an RSA-2048 rather than RSA-4096 key.

### Which certificate, and how it relates to Part 1's two Samsung PKI roles

The certificate embedded here is **not** the same one used to encrypt the pre-request in the `AT+ENGMODES=0,1,...` exchange covered in Part 1. Extracting it shows:

- **Issuer:** `CN=EngineeringMode <ticket-id>_eas00 ROOT`
- **Subject:** `CN=EngineeringMode, UID=SVR-P:<server-build-id>:V1:EM`
- **Key usage:** Digital Signature, Non-Repudiation — not Key Encipherment

That last line is the giveaway: this is a **signing-only** certificate, used purely to verify the `0x0001` RSA signature over the finished token (`root_ca_type` selecting the matching embedded Samsung root inside `FUN_00104d04`, per Part 1). The certificate Part 1 covered (`CN=EBS Protocol CA`, with a *Key Encipherment* usage) plays a different role entirely: it's the one the pre-request flow uses to RSA-wrap the AES session key that protects the pre-request in transit. Put together, Samsung's token-issuance PKI keeps two separate certificate roles in play — one to protect the pre-request on the wire, a different one to sign the finished, delivered token — and `engmode.mbn` only ever trusts each one for its own purpose: a signing certificate presented where an encryption certificate is expected (or vice versa) fails the corresponding check in `FUN_00104d04`/`FUN_00105838`.

## What varies across samples, and why it doesn't help

Across every token analyzed — recent B2B-portal issues for Galaxy S25 / S25+ / S26 Ultra, and one older internally-generated sample — the container format itself never changes. What varies is exactly the set of optional fields a given issuance path chooses to populate: `DEVI`'s model/IMEI, `ISSU`'s nonce vs. operator/IP fields, `MODB`'s approval-note sub-tag, `TOKE`'s protocol-revision byte. `engmode.mbn`'s parser handles all of this by walking each section's own declared element count rather than assuming a fixed shape — exactly the flexibility a TLV format is for.

None of that flexibility touches the one thing that actually matters for security: **every section from the container magic through the end of `GRDB` is covered by the single RSA-4096 signature in `INTE`.** Change the model string, the DID, the IMEI, a validity date, or a `max_uses` quota in a copy of a real token, and the SHA-256 digest `engmode.mbn` recomputes over those bytes no longer matches what the embedded signature attests to — the signature check inside the TrustZone verification path documented in Part 1 fails outright, and the token is rejected before any mode bit is ever set in `DAT_001a3d20` (Part 2). That's the whole reason the format can afford to be this transparent and well-documented: readability of the container doesn't translate into forgeability, because nothing in it is trusted until the signature over it checks out against a Samsung-controlled root.

## Reference: ENGRSS0002 tags and sub-tags

| Section | Section-level role | Key sub-tags |
|---|---|---|
| Header (0x000–0x02D) | Magic, header size, 8-slot section-offset table | — |
| `TOKE` | Per-ticket transaction identity | 0x0001 transaction ID · 0x0002 type/version · 0x0003 state · 0x0005 protocol revision |
| `DEVI` | Hardware binding | 0x0001 model · 0x0002 DID (only mandatory field) · 0x0003 IMEI |
| `ISSU` | Issuance traceability | 0x0001 operator/tool · 0x1001 license type · 0x1002 server IP · 0x0003 session nonce |
| `VALI` | Validity window | 0x0001 start date · 0x0002 end date (`99999999` = no expiry) |
| `MODE` | Sub-TLV list of authorized mode IDs | two 4-byte `[uint16 ID][uint16 Length][Value]` entries, e.g. `0x0005` = `MODE_DEBUG_CP`, `0x0003` = `MODE_CUST_KERNEL` |
| `MODB` | Per-mode name, description and quota | 0x0001 group ID · 0x0004 `max_uses` · 0x0005 consumed count · 0x0007 optional approval note |
| `GRDB` | Functional-group catalog | fixed ID + name + description records |
| `INTE` | Cryptographic seal (always last) | 0x0001 RSA-4096 signature over everything before it · 0x0002 signer's X.509 cert |

*As with Parts 1 and 2, this is a snapshot of one firmware/server generation — sub-tag sets (especially the optional ones) may be added or dropped across Samsung server-side or firmware revisions.*
