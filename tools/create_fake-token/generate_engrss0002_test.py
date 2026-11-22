#!/usr/bin/env python3
# Générateur de fixture ENGRSS0002 — usage de test / rétro-ingénierie uniquement.
# La signature RSA est volontairement invalide : ce fichier ne constitue PAS
# un jeton Samsung et ne peut pas autoriser un mode Engineering.

import hashlib
import os
import struct
from datetime import datetime

print("Script created by Informatique Pro; I haven't translated it into English yet—sorry!")

MAGIC = b"ENGRSS0002"
HEADER_SIZE = 0x2E  # 10 octets de magic + 4 de taille + 8 offsets de 4 octets


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def pack_tlv(tag_id: int, data: bytes) -> bytes:
    """Convention du script fourni : [tag:uint16][length:uint16][value]."""
    if len(data) > 0xFFFF:
        raise ValueError("Valeur TLV trop longue pour un champ uint16.")
    return struct.pack("<HH", tag_id, len(data)) + data


def pack_section(tag_name: str, payload: bytes, item_count: int) -> bytes:
    """Convention observée dans le script fourni : tag + taille + compte + payload."""
    if len(tag_name) != 4:
        raise ValueError("Un tag de section doit faire exactement 4 caractères.")
    return tag_name.encode("ascii") + struct.pack("<II", len(payload), item_count) + payload


def ascii_bytes(value: str, field: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} doit contenir uniquement des caractères ASCII.") from exc


def fixed_ascii(value: str, width: int, field: str) -> bytes:
    raw = ascii_bytes(value, field)
    if len(raw) > width:
        raise ValueError(f"{field} ne doit pas dépasser {width} octets.")
    return raw.ljust(width, b"\x00")


def build_modb_entry(mode_id: int, name: str, desc: str,
                     limit_enabled: int, max_uses: int) -> bytes:
    name_buf = fixed_ascii(name, 32, "Nom du mode")
    desc_buf = fixed_ascii(desc, 128, "Description du mode")
    sub_tlvs = b"".join([
        pack_tlv(0x0001, u16(limit_enabled)),
        pack_tlv(0x0002, b"\x00"),
        pack_tlv(0x0003, b"\x00"),
        pack_tlv(0x0004, u32(max_uses)),
        pack_tlv(0x0005, b"\x00"),
        pack_tlv(0x0006, b"\x00"),
    ])
    return u16(mode_id) + name_buf + desc_buf + u32(len(sub_tlvs)) + u32(6) + sub_tlvs


def build_grdb_entry(group_id: int, group_name: str, desc: str, mode_id: int) -> bytes:
    gname_buf = fixed_ascii(group_name, 32, "Nom du groupe")
    desc_buf = fixed_ascii(desc, 128, "Description du groupe")
    sub_tlvs = pack_tlv(0x0001, u16(mode_id))
    return u16(group_id) + gname_buf + desc_buf + u32(len(sub_tlvs)) + u32(1) + sub_tlvs


def validate_imei(imei: str) -> None:
    if imei and (not imei.isdigit() or len(imei) not in (14, 15, 16)):
        raise ValueError("IMEI : saisir 14, 15 ou 16 chiffres, ou laisser vide.")


def validate_did(did: str) -> None:
    if len(did) != 16 or any(c not in "0123456789abcdefABCDEF" for c in did):
        raise ValueError("Le DID doit contenir exactement 16 caractères hexadécimaux.")


def validate_date(date_text: str, field: str) -> None:
    try:
        datetime.strptime(date_text, "%Y%m%d")
    except ValueError as exc:
        raise ValueError(f"{field} doit être au format AAAAMMJJ.") from exc


def generate_token(model: str, did: str, imei: str, token_id: str,
                   start_date: str, end_date: str,
                   kernel_quota: int, cp_quota: int,
                   cert_path: str | None = None) -> bytes:
    validate_did(did)
    validate_imei(imei)
    validate_date(start_date, "Date de début")
    if end_date != "99999999":
        validate_date(end_date, "Date de fin")
    if start_date > end_date:
        raise ValueError("La date de début doit précéder la date de fin.")
    if not (0 <= kernel_quota <= 0xFFFFFFFF and 0 <= cp_quota <= 0xFFFFFFFF):
        raise ValueError("Les quotas doivent être compris entre 0 et 4294967295.")

    # 1. TOKE
    toke_payload = b"".join([
        pack_tlv(0x0001, ascii_bytes(token_id, "Token ID")),
        pack_tlv(0x0002, u16(1)),
        pack_tlv(0x0003, u16(1)),
        pack_tlv(0x0005, b"\x04"),
    ])
    sec_toke = pack_section("TOKE", toke_payload, 4)

    # 2. DEVI — identifiants fournis par l'utilisateur
    devi_fields = [
        pack_tlv(0x0001, ascii_bytes(model, "Modèle")),
        pack_tlv(0x0002, ascii_bytes(did, "DID")),
    ]
    if imei:
        devi_fields.append(pack_tlv(0x0003, ascii_bytes(imei, "IMEI")))
    devi_payload = b"".join(devi_fields)
    sec_devi = pack_section("DEVI", devi_payload, len(devi_fields))

    # 3. ISSU — valeurs de test, sans identité interne Samsung
    issu_payload = b"".join([
        pack_tlv(0x0001, b"LOCAL-TEST"),
        pack_tlv(0x1001, b"TEST-BinaryLicense"),
        pack_tlv(0x1002, b"127.0.0.1"),
    ])
    sec_issu = pack_section("ISSU", issu_payload, 3)

    # 4. MODE — encodage conservé du script fourni (deux uint32)
    mode_payload = pack_tlv(0x0001, u16(5)) + pack_tlv(0x0002, u16(3))
    sec_mode = pack_section("MODE", mode_payload, 2)

    # 5. VALI
    vali_payload = b"".join([
        pack_tlv(0x0001, ascii_bytes(start_date, "Date de début")),
        pack_tlv(0x0002, ascii_bytes(end_date, "Date de fin")),
    ])
    sec_vali = pack_section("VALI", vali_payload, 2)

    # 6. MODB
    modb_payload = (
        build_modb_entry(
            0x0003, "MODE_CUST_KERNEL",
            "TEST FIXTURE ONLY - INVALID SIGNATURE",
            1, kernel_quota
        )
        + build_modb_entry(
            0x0005, "MODE_DEBUG_CP",
            "TEST FIXTURE ONLY - INVALID SIGNATURE",
            0, cp_quota
        )
    )
    sec_modb = pack_section("MODB", modb_payload, 2)

    # 7. GRDB
    grdb_payload = (
        build_grdb_entry(0x0001, "Binary Flashing", "TEST FIXTURE ONLY", 0x0003)
        + build_grdb_entry(0x0004, "Debugging FT", "TEST FIXTURE ONLY", 0x0005)
    )
    sec_grdb = pack_section("GRDB", grdb_payload, 2)

    # 8. INTE — signature aléatoire volontairement invalide.
    # Le certificat est soit fourni par l'utilisateur, soit remplacé par un
    # bloc factice. Aucun certificat X.509 Samsung n'est créé ici.
    fake_signature = os.urandom(512)
    if cert_path:
        with open(cert_path, "rb") as cert_file:
            cert_der = cert_file.read()
        if not cert_der:
            raise ValueError("Le fichier de certificat est vide.")
    else:
        cert_der = b"TEST-NOT-A-REAL-X509-CERTIFICATE" + bytes(128)

    inte_payload = (
        pack_tlv(0x0001, fake_signature)
        + pack_tlv(0x0002, cert_der)
    )
    sec_inte = pack_section("INTE", inte_payload, 2)

    # L'offset 0x0A contient la taille de l'en-tête (0x2E), comme dans les jetons officiels
    # Ordre physique des sections
    sections = [
        sec_toke, sec_devi, sec_issu, sec_mode,
        sec_vali, sec_modb, sec_grdb, sec_inte
    ]

    # 1. Calcul des offsets de chaque section (DOIT être fait avant header)
    offsets = []
    cursor = HEADER_SIZE
    for sec in sections:
        offsets.append(cursor)
        cursor += len(sec)

    total_size = cursor

    # 2. Construction de l'en-tête avec HEADER_SIZE (0x2E) à l'offset 0x0A
    header = MAGIC + u32(HEADER_SIZE) + b"".join(u32(x) for x in [
        offsets[0], offsets[1], offsets[2], offsets[3],
        offsets[4], offsets[7], offsets[5], offsets[6]
    ])

    if len(header) != HEADER_SIZE:
        raise AssertionError("Taille d'en-tête inattendue.")

    body_before_inte = b"".join(sections[:-1])
    digest = hashlib.sha256(header + body_before_inte).hexdigest()
    print(f"[i] SHA-256 du contenu avant INTE : {digest}")
    print("[i] Signature RSA : aléatoire et volontairement invalide.")

    result = header + b"".join(sections)
    if len(result) != total_size:
        raise AssertionError("La taille finale ne correspond pas à l'en-tête.")
    return result


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix} : ").strip()
    return value if value else (default or "")


def main() -> None:
    print("=== Générateur de fixture ENGRSS0002 (signature invalide) ===")
    print("N'utilisez que des identifiants de test ou ceux que vous êtes autorisé à traiter.\n")

    model = ask("Modèle (ex. SM-S931B)")
    did = ask("DID (16 caractères hexadécimaux)")
    imei = ask("IMEI (laisser vide si absent)")
    token_id = ask("Token ID", "TEST-TOKEN-000001")
    start_date = ask("Date de début AAAAMMJJ", "20261121")
    end_date = ask("Date de fin AAAAMMJJ ou 99999999", "99999999")
    kernel_quota = int(ask("Quota MODE_CUST_KERNEL", "10"))
    cp_quota = int(ask("Quota MODE_DEBUG_CP", "9999"))
    cert_path = ask("Chemin d'un certificat DER de test (laisser vide pour bloc factice)")
    output_path = ask("Nom du fichier de sortie", "test_engrss0002.bin")

    blob = generate_token(
        model=model,
        did=did,
        imei=imei,
        token_id=token_id,
        start_date=start_date,
        end_date=end_date,
        kernel_quota=kernel_quota,
        cp_quota=cp_quota,
        cert_path=cert_path or None,
    )

    with open(output_path, "wb") as output_file:
        output_file.write(blob)

    print(f"\n[+] Fichier créé : {output_path}")
    print(f"[+] Taille : {len(blob)} octets")
    print("[!] Fixture de test uniquement : elle ne possède aucune signature valide.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(f"[ERREUR] {error}")
