# mcls-vanet
 Hybrid signcryption scheme Python implementation
## Description
A python implementation of an Anonymous Multi-receiver Certificateless Hybrid Signcryption Scheme, providing both digital signature and encryption functionalities.
## Functionalities
### Certificateless Public Key Cryptography
Certificateless public key cryptography requires a trusted third party called (a key generation center (KGC)) to generate a part of a private key of the user while users generate the full private and public key pair. More specifically, the KGC generates a partial private key `ppk` of the user, while the user generates a secret value `sv` and a public key `pk` using that secret value. Finally, the user combines a `ppk` and a `sv` to compute a full private key `sk`.
### Hybrid Signcryption
Signcryption is an asymmetric key cryptography technique that combines digital signature and encryption operations to generate a signcrypted ciphertext `CT`. Whereas hybrid signcryption combines symmetric and asymmetric key cryptography that provides asymmetric signature and symmetric encryption. 

# Implementation
This project implements Elliptic Curve Signcryption using  ECDSA (Elliptic Curve Digital Signature Algorithm) and AES (Advanced Encryption Standard) for secure communication.
It performs:
 - Key generation using elliptic curve
 - Diffie-Hellman (ECDH) key exchange
 - Hybrid Signcryption (ECDSA + AES)
 - Unsigncryption (Message verification)
## Features
