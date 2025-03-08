# mcls-vanet
 Hybrid signcryption scheme Python implementation
## Description
A python implementation of an Anonymous Multi-receiver Certificateless Hybrid Signcryption Scheme, providing both digital signature and encryption functionalities.
## Functionalities
Certificateless public key cryptography requires a trusted third party called (a key generation center (KGC)) to generate a part of a private key of the user while users generate the full private and public key pair. More specifically, the KGC generates a partial private key `ppk` of the user, while the user generates a secret value `sv` and a public key `pk` using that secret value. Finally, the user combines a `ppk` and a `sv` to compute a full private key `sk`.
  
