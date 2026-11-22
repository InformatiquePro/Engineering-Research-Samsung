##Generate EM Token

This script (not yet translated into English, sorry!) generates syntactically valid EM tokens, but they won't actually work because I have no way to sign them!  
To use it, simply run it and answer the questions (Model, DID, IMEI, etc.).  
I built this script based on my own analysis; it will certainly evolve over time!  
Example of usage:  
```text
Script created by Informatique Pro; I haven't translated it into English yet—sorry!
=== Générateur de fixture ENGRSS0002 (signature invalide) ===
N'utilisez que des identifiants de test ou ceux que vous êtes autorisé à traiter.

Modèle (ex. SM-S931B) : SM-S936B
DID (16 caractères hexadécimaux) : XXXXXXXXXXXXXXXX
IMEI (laisser vide si absent) : XXXXXXXXXXXXXXX
Token ID [TEST-TOKEN-000001] : 
Date de début AAAAMMJJ [20261121] : 
Date de fin AAAAMMJJ ou 99999999 [99999999] : 
Quota MODE_CUST_KERNEL [10] : 
Quota MODE_DEBUG_CP [9999] : 
Chemin d'un certificat DER de test (laisser vide pour bloc factice) : 
Nom du fichier de sortie [test_engrss0002.bin] : 
[i] SHA-256 du contenu avant INTE : c1eca0f8f8e3b477685573e5180db332404aa4d14ac01f2390d358c1232bc697
[i] Signature RSA : aléatoire et volontairement invalide.

[+] Fichier créé : test_engrss0002.bin
[+] Taille : 1756 octets
[!] Fixture de test uniquement : elle ne possède aucune signature valide.
```
I have intentionally removed some elements from this excerpt to ensure zero risk.  
