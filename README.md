# MCLS-VANET Library
The library provides implementation of an Anonymous Multi-receiver Certificateless Hybrid Signcryption Scheme, for digital signature and encryption functionalities.
This project implements Elliptic Curve Signcryption using  ECDSA (Elliptic Curve Digital Signature Algorithm) and AES (Advanced Encryption Standard) for secure communication.
It performs:

 - Key generation using elliptic curve
 - Diffie-Hellman (ECDH) key exchange
 - Hybrid Signcryption (ECDSA + AES)
 - Unsigncryption (Message verification)

# Cryptographic functionalities 

### Certificateless Public Key Cryptography
Certificateless public key cryptography requires a trusted third party called (a key generation center (KGC)) to generate a part of a private key of the user while users generate the full private and public key pair. More specifically, the KGC generates a partial private key `ppk` of the user, while the user generates a secret value `sv` and a public key `pk` using that secret value. Finally, the user combines a `ppk` and a `sv` to compute a full private key `sk`.

### Hybrid Signcryption
Signcryption is an asymmetric key cryptography technique that combines digital signature and encryption operations to generate a signcrypted ciphertext `CT`. Whereas hybrid signcryption combines symmetric and asymmetric key cryptography that provides asymmetric signature and symmetric encryption.

### Features
- Elliptic Curve Key Generation (NIST P-256)
- Partial and Full Key Computation
- Signcryption using AES + ECC
- ECDSA Digital Signature and Verification
- SHA-256 Hashing for Key Derivation

### Code Structure 

| Operation | Description |
| --------- | ----------- |
| Elliptic curve key generation | Generates ECC-based public and private keys |
| Signcryption | Encrypts and Signs messahe using ECDSA and AES |
| Unsigncryption | Decrypts message and verifies signature |
| AES Encryption | Encrypts message using AES in CFB mode |

## Installation

To install library please run pip install with supplied requirements.txt file as in example from below:

```bash
pip install -r requirements.txt
```

### Run the code

To run the test with the library please run following:

```bash
python [mcls-vanet.py](mcls-vanet.py)
```

### Bibliography 
Alia Umrani, Apurva K. Vangujar, and Paolo Palmieri. "Anonymous Multi-Receiver Certificateless Hybrid Signcryption for Broadcast Communication." In ICISSP, pp. 733-744. 2024.[https://www.scitepress.org/Papers/2024/123534/123534.pdf]
