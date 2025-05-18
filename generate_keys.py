
HMAC_KEY_SIZE = 32 # bytes
RSA_KEY_SIZE = 2048 # bits

def generate_rsa_keys(private_key_file="rsa_private.pem", public_key_file="rsa_public.pem", key_size=RSA_KEY_SIZE):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Write private key to file
    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Generate and save public key
    public_key = private_key.public_key()
    with open(public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[RSA KEYS GENERATED] → {private_key_file}, {public_key_file}")

def generate_hmac_key(filename="hmac.pem", key_size=HMAC_KEY_SIZE):
    import os
    import base64
    key = os.urandom(key_size)
    key_base64 = base64.b64encode(key)  
    with open(filename, "wb") as f:
        f.write(key_base64)
    print(f"[HMAC KEY ({key_size} bytes) in {filename}]")
    return key

# %%
generate_rsa_keys()
generate_hmac_key()