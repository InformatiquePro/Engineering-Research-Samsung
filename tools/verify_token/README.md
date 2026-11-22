##Verify EM Token

This script allows you to verify whether an EM token is correctly signed. Apologies—it is still in French, as I haven't translated it into English yet!  
To use it, install the `cryptography` Python module.  
Then, place the `engmode.mbn` file from your firmware (or the one I provided in the `Samsung-ui9_sept26` folder in this repository) into the same directory—note that using mine will rely on the signatures present in my firmware, which may differ from yours. Also, place `steady.bin` (the token) in the same folder.

Example of the output with a genuine, valid token:

```text
Script created by Informatique Pro; I haven't translated it into English yet—sorry!
[*] 19 clés publiques chargées depuis engmode.mbn

============================================================
Jeton à 0x0 | Taille totale : 3231 octets (0xC9F)
============================================================
  [TOKE] (offset 0x2E, taille 37o, 4 items):
    - Tag 1: 'XXXXXXXXXXXXXXX'
    - Tag 2: 0100
    - Tag 3: 0100
    - Tag 4: 00
  [DEVI] (offset 0x5F, taille 51o, 3 items):
    - Tag 1: 'SM-S931B'
    - Tag 2: 'XXXXXXXXXXXXXXXX'
    - Tag 3: 'XXXXXXXXXXXXXXX'
  [ISSU] (offset 0x9E, taille 45o, 3 items):
    - Tag 1: 'dh0.cho'
    - Tag 4097: 'BinaryLicense'
    - Tag 4098: 'XXX.XXX.XXX.XXX'
  [VALI] (offset 0xEB, taille 24o, 2 items):
    - Tag 1: '20260330'
    - Tag 2: '99999999'
  [MODB] (offset 0x10F, taille 488o, 2 entrées):
    - MODE_CUST_KERNEL
    - Allow customized kernel(not eng, userdebug, PBS, RBS) binary to be flashed and booted
    - MODE_DEBUG_CP
    - Allow to show debug message for CP
    - [Base64] CP 관련 debug 메세지 출력을 허용합니다.
  [GRDB] (offset 0x303, taille 350o, 2 entrées):
    - Binary Flashing
    - Allow to flash 
    - Debugging FT
    - Debugging FT

  [CERT] Subject CN : EngineeringMode | Issuer CN : EngineeringMode 24110200_eas00 ROOT
  [+] Certificat X.509 AUTHENTIQUE (Root CA à 0xF7C78, 4096 bits)
  [+] Signature RSA-4096 du jeton VALIDE (SHA-256: XXXXXXXX)
```
I have intentionally removed some elements from this excerpt to ensure zero risk (yes, even the sha256sum!)
