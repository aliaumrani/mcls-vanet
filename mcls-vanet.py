
# Initialize elliptic curve (NIST P-256)
curve = ec.SECP256R1()

# Generate a random generator value (ensuring it is correctly derived)
generator = ec.generate_private_key(curve).public_key().public_numbers().x

# Generate Master Key Pair (Master Private Key & Corresponding Public Key)
master_private_key = ec.generate_private_key(curve)
master_public_key = master_private_key.public_key()

# Generate Registration Authority (RA) Key Pair
RA_private_key = ec.generate_private_key(curve)
RA_public_key = RA_private_key.public_key()

# Generate Sender's and Receiver's Secret Values (Private Keys)
secret_value_s = int.from_bytes(os.urandom(32), byteorder='big')  # Sender's secret key
secret_value_r = int.from_bytes(os.urandom(32), byteorder='big')  # Receiver's secret key

# Generate Public Keys for Sender & Receiver
public_key_s = ec.derive_private_key(secret_value_s, curve, default_backend()).public_key()
public_key_r = ec.derive_private_key(secret_value_r, curve, default_backend()).public_key()

# Generate a random value α for use in signcryption
alpha = secrets.randbelow(generator)
alpha_private_key = ec.derive_private_key(alpha, curve, default_backend())

# Compute R = α * Generator
R = alpha * generator

# Generate a 160-bit Random Binary String for PID
D_R = secrets.randbits(160)
DR_integer = D_R  # Convert to integer

# Compute PID (Ensuring it fits within 160-bit)
for_H0 = RA_private_key.exchange(ec.ECDH(), alpha_private_key.public_key())  # ECDH Key Exchange
PID_1 = (DR_integer ^ int.from_bytes(hashlib.sha256(for_H0).digest(), byteorder='big')) & ((1 << 160) - 1)

# Convert PID to 20 bytes (160-bit representation)
PID_bytes = PID_1.to_bytes(20, byteorder='big')

# Compute Partial Private Key (PPK)
Q_PID = hashlib.sha256(PID_bytes + master_public_key.public_bytes(
    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
QPID_as_integer = int.from_bytes(Q_PID, byteorder='big')
ppk = master_private_key.private_numbers().private_value * QPID_as_integer  # Partial Private Key Computation

# Compute Full Private Key for Sender
full_private_key = ppk + secret_value_s

# **Signcryption Phase**

# Compute Z1 = ppk * QPID_as_integer
Z1 = ppk * QPID_as_integer

# Compute Z2 = secret_value_s * public_key_r.x
Z2 = secret_value_s * public_key_r.public_numbers().x

# Compute ψ = Z1 * Z2
psi = Z1 * Z2

# Compute U = r * Generator (Random value multiplied with Generator)
r = secrets.randbelow(generator)
U = r * generator

# Convert ψ to bytes
psi_bytes = psi.to_bytes((psi.bit_length() + 7) // 8, byteorder='big')

# Hash ψ to derive AES Key (Symmetric Key for Encryption)
K = hashlib.sha256(psi_bytes).digest()

# Generate a 160-bit Random Message (Hex)
message = secrets.token_hex(20)  # 160-bit random message
message_bytes = bytes.fromhex(message)  # Convert to bytes

# **AES Encryption**
iv = os.urandom(16)  # Generate random initialization vector (IV)
cipher = Cipher(algorithms.AES(K), modes.CFB(iv), backend=default_backend())  # AES in CFB mode
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

# Compute `f_integer` (Hash of concatenated values)
concatenation = (
    message_bytes + psi_bytes +
    public_key_s.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo) +
    public_key_r.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
)
f = hashlib.sha256(concatenation).digest()
f_integer = int.from_bytes(f, byteorder='big')

# Compute U' = f_integer * Generator
U_prime = f_integer * generator

# **ECDSA Signature Generation**
private_key_s_ecdsa = ecdsa.SigningKey.from_secret_exponent(secret_value_s, curve=ecdsa.SECP256k1)
ecdsa_signature = private_key_s_ecdsa.sign(ciphertext, sigencode=sigencode_der)

# **Unsigncryption Phase**
# Compute Z1' = ppk * QPID_as_integer
Z1_prime = ppk * QPID_as_integer

# Compute Z2' = secret_value_r * public_key_s.x
Z2_prime = secret_value_r * public_key_s.public_numbers().x

# Compute U' = f_integer * Generator
U_prime = f_integer * generator

# **Decryption Phase**
decipher = Cipher(algorithms.AES(K), modes.CFB(iv), backend=default_backend())  # AES Cipher
decryptor = decipher.decryptor()
decrypted_message_bytes = decryptor.update(ciphertext) + decryptor.finalize()
decrypted_message = decrypted_message_bytes.hex()

# **ECDSA Signature Verification**
public_key_s_ecdsa = private_key_s_ecdsa.get_verifying_key()
try:
    public_key_s_ecdsa.verify(ecdsa_signature, ciphertext, sigdecode=sigdecode_der)
    signature_status = "Signature verification passed."
except ecdsa.BadSignatureError:
    signature_status = "Signature verification failed."


print("\nOriginal Message:", message)
print("Decrypted Message:", decrypted_message)
print(signature_status)
