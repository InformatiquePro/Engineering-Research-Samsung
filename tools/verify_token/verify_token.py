import base64
import hashlib
import re
import struct
import warnings
from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

print("Script created by Informatique Pro; I haven't translated it into English yet—sorry!")

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def extract_all_pubkeys(mbn_path):
    with open(mbn_path, "rb") as f:
        data = f.read()
    keys = []
    pos = 0
    while True:
        idx = data.find(b"\x30\x82", pos)
        if idx == -1:
            break
        if idx + 4 <= len(data):
            der_len = struct.unpack_from(">H", data, idx + 2)[0] + 4
            if idx + der_len <= len(data):
                try:
                    pub = serialization.load_der_public_key(data[idx : idx + der_len])
                    keys.append((idx, der_len, pub))
                    pos = idx + der_len
                    continue
                except Exception:
                    pass
        pos = idx + 1
    return keys

def parse_simple_section(token, pos):
    magic = token[pos:pos+4].decode("ascii", errors="replace")
    sec_size, count = struct.unpack_from("<II", token, pos + 4)
    cursor = pos + 12
    items = []
    for _ in range(count):
        tag, length = struct.unpack_from("<HH", token, cursor)
        items.append((tag, token[cursor + 4 : cursor + 4 + length]))
        cursor += 4 + length
    return magic, sec_size, items

def dump_simple_section(token, name):
    pos = token.find(name.encode())
    if pos == -1:
        return
    _, sec_size, items = parse_simple_section(token, pos)
    print(f"  [{name}] (offset 0x{pos:X}, taille {sec_size}o, {len(items)} items):")
    for tag, val in items:
        txt = val.rstrip(b"\x00").decode("ascii", errors="ignore")
        if txt and len(txt) >= 2 and txt.isprintable():
            print(f"    - Tag {tag}: '{txt}'")
        else:
            print(f"    - Tag {tag}: {val.hex()}")

def dump_nested_section(token, name):
    pos = token.find(name.encode())
    if pos == -1:
        return
    sec_size, count = struct.unpack_from("<II", token, pos + 4)
    print(f"  [{name}] (offset 0x{pos:X}, taille {sec_size}o, {count} entrées):")
    sec_bytes = token[pos + 12 : pos + 12 + sec_size]
    for m in re.finditer(rb"[\x20-\x7e]{4,}", sec_bytes):
        s = m.group(0).decode("ascii")
        if s.endswith("==") and len(s) > 20:
            try:
                print(f"    - [Base64] {base64.b64decode(s).decode('utf-8')}")
                continue
            except Exception:
                pass
        print(f"    - {s}")

def verify_token_at(data, base_offset, all_keys):
    next_tok = data.find(b"ENGRSS0002", base_offset + 10)
    token = data[base_offset:] if next_tok == -1 else data[base_offset:next_tok]
    print(f"\n============================================================")
    print(f"Jeton à 0x{base_offset:X} | Taille totale : {len(token)} octets (0x{len(token):X})")
    print(f"============================================================")

    hdr_field = struct.unpack_from("<I", token, 0x0A)[0]
    if hdr_field != 0x2E:
        print(f"  [!] Avertissement en-tête : champ 0x0A = 0x{hdr_field:X} (attendu: 0x2E)")

    for sec in ["TOKE", "DEVI", "ISSU", "VALI"]:
        dump_simple_section(token, sec)
    for sec in ["MODB", "GRDB"]:
        dump_nested_section(token, sec)

    off_inte = token.find(b"INTE")
    if off_inte == -1:
        print("\n  [X] INVALIDE : Section INTE introuvable.")
        return

    _, _, inte_items = parse_simple_section(token, off_inte)
    sig_bytes = next((v for t, v in inte_items if t == 1), None)
    cert_der = next((v for t, v in inte_items if t == 2), None)

    if not sig_bytes or not cert_der:
        print("\n  [X] INVALIDE : Signature (Tag 1) ou Certificat (Tag 2) manquant dans INTE.")
        return

    # 1. Chargement et validation du certificat X.509
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        preview = cert_der[:32].decode("ascii", errors="replace")
        print(f"\n  [X] CERTIFICAT INVALIDE : Impossible de parser le certificat X.509 DER ({type(e).__name__}).")
        print(f"      Contenu brut Tag 2 : '{preview}...'")
        print("      Raison : Bloc factice ou corrompu (non conforme ASN.1 DER).")
        return

    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    print(f"\n  [CERT] Subject CN : {cn} | Issuer CN : {issuer_cn}")

    root_ok = False
    for foff, _, pub in all_keys:
        try:
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            print(f"  [+] Certificat X.509 AUTHENTIQUE (Root CA à 0x{foff:X}, {pub.key_size} bits)")
            root_ok = True
            break
        except Exception:
            continue
    if not root_ok:
        print(f"  [!] Certificat X.509 NON RECONNU : Aucune clé Root CA de ce engmode.mbn ne correspond à '{issuer_cn}'.")

    # 2. Vérification RSA-4096 PKCS#1 v1.5 brut sur token[0x0 : off_inte]
    if len(sig_bytes) != 512:
        print(f"  [X] SIGNATURE INVALIDE : Taille = {len(sig_bytes)} octets (attendu : 512 octets pour RSA-4096).")
        return

    pub_nums = cert.public_key().public_numbers()
    decrypted = pow(int.from_bytes(sig_bytes, "big"), pub_nums.e, pub_nums.n).to_bytes(512, "big")
    expected_padding = b"\x00\x01" + (b"\xff" * (512 - 35)) + b"\x00"
    actual_sha256 = hashlib.sha256(token[:off_inte]).digest()

    if decrypted[:480] != expected_padding:
        print("  [X] SIGNATURE RSA-4096 INVALIDE : Padding PKCS#1 v1.5 absent (octets aléatoires ou mauvaise clé privée).")
    elif decrypted[-32:] != actual_sha256:
        print("  [X] SIGNATURE RSA-4096 INVALIDE : Le condensat SHA-256 ne correspond pas au contenu du jeton (jeton modifié après signature).")
    else:
        print(f"  [+] Signature RSA-4096 du jeton VALIDE (SHA-256: {actual_sha256.hex()})")

def main():
    all_keys = extract_all_pubkeys("engmode.mbn")
    print(f"[*] {len(all_keys)} clés publiques chargées depuis engmode.mbn")
    with open("steady.bin", "rb") as f:
        steady = f.read()

    pos = 0
    while True:
        idx = steady.find(b"ENGRSS0002", pos)
        if idx == -1:
            break
        verify_token_at(steady, idx, all_keys)
        pos = idx + 10

if __name__ == "__main__":
    main()
