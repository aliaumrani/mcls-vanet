# --- Setup ---
curve = ec.SECP256R1()
curve_order = ECDSA_SECP256r1.order

# Master private key (KGC)
master_private_key = ec.generate_private_key(curve)
master_public_key = master_private_key.public_key()

# Registration Authority (RA)
RA_private_key = ec.generate_private_key(curve)
RA_public_key = RA_private_key.public_key()

# Sender and Receiver secret values
x_s = secrets.randbelow(curve_order)
x_r = secrets.randbelow(curve_order)

private_key_s = ec.derive_private_key(x_s, curve, default_backend())
private_key_r = ec.derive_private_key(x_r, curve, default_backend())
public_key_s = private_key_s.public_key()
public_key_r = private_key_r.public_key()

# α for pseudo-identity phase
alpha = secrets.randbelow(curve_order)
alpha_private_key = ec.derive_private_key(alpha, curve, default_backend())
R = alpha_private_key.public_key()

# PID calculation
D_R = secrets.randbits(160)
shared_secret = RA_private_key.exchange(ec.ECDH(), alpha_private_key.public_key())
PID_1 = (D_R ^ int.from_bytes(hashlib.sha256(shared_secret).digest(), byteorder='big')) & ((1 << 160) - 1)
PID_bytes = PID_1.to_bytes(20, byteorder='big')

# Q_PID and PPK
Q_PID = hashlib.sha256(PID_bytes + master_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
QPID_as_integer = int.from_bytes(Q_PID, byteorder='big')
ppk_scalar = (master_private_key.private_numbers().private_value * QPID_as_integer) % curve_order

# Partial private key (d_s)
d_s_scalar = ppk_scalar
d_s_key = ec.derive_private_key(d_s_scalar, curve, default_backend())

# --- Signcryption Phase (Sender Side) ---

# 1. Compute Y1 = d_s * Q_PID (remains as per protocol)
Y1_scalar = (d_s_scalar * QPID_as_integer) % curve_order
Y1_point = ec.derive_private_key(Y1_scalar, curve, default_backend()).public_key()

# 2. Compute shared secret via ECDH (Z2)
Z2_shared = private_key_s.exchange(ec.ECDH(), public_key_r)

# 3. Derive K_s = H2(Y1 || Z2_shared)
Y1_bytes = Y1_point.public_bytes(encoding=serialization.Encoding.DER,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
K_sender = hashlib.sha256(Y1_bytes + Z2_shared).digest()
print("Encryption Key (K):", K_sender.hex())

# AES Encryption
message = secrets.token_hex(20)
message_bytes = bytes.fromhex(message)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(K_sender), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

# Signature Generation (ECDSA)
private_key_s_ecdsa = SigningKey.from_secret_exponent(x_s, curve=ECDSA_SECP256r1)
ecdsa_signature = private_key_s_ecdsa.sign(ciphertext, sigencode=sigencode_der)

# --- Unsigncryption Phase (Receiver Side) ---

# 1. Use received Y1 (same from sender)
Y1_prime_point = Y1_point  # received from sender

# 2. Compute shared secret via ECDH
Z2_prime_shared = private_key_r.exchange(ec.ECDH(), public_key_s)

# 3. Derive K_r = H2(Y1 || Z2')
Y1_prime_bytes = Y1_prime_point.public_bytes(encoding=serialization.Encoding.DER,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
K_receiver = hashlib.sha256(Y1_prime_bytes + Z2_prime_shared).digest()
print("Decryption Key (K'):", K_receiver.hex())

# AES Decryption
decipher = Cipher(algorithms.AES(K_receiver), modes.CFB(iv), backend=default_backend())
decryptor = decipher.decryptor()
decrypted_message_bytes = decryptor.update(ciphertext) + decryptor.finalize()
decrypted_message = decrypted_message_bytes.hex()

# Signature Verification
public_key_s_ecdsa = private_key_s_ecdsa.get_verifying_key()
try:
    public_key_s_ecdsa.verify(ecdsa_signature, ciphertext, sigdecode=sigdecode_der)
    signature_status = "Signature verification passed."
except BadSignatureError:
    signature_status = "Signature verification failed."

# --- Output ---
print("\nOriginal Message     :", message)
print("Decrypted Message    :", decrypted_message)
print("Signature Verification:", signature_status)
