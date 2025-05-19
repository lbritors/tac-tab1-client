# %%
import asyncio
import json
import os
import jwt
import datetime
import ssl
import base64
from aiohttp import web
import aiosqlite
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

load_dotenv()

PORT = 5001
KEY_SIZE = 32 # bytes
TOKEN_EXPIRATION_SECONDS = 3600 #1 hora
DB_PATH = "auth_database.db"
HMAC_KEY_FILE = "../hmac.pem"
CREDENTIALS_FILE = "credentials.json"
RSA_PUB_KEY_FILE = "rsa_public.pem"
RSA_PRIV_KEY_FILE = "rsa_private.pem"
RSA_ALGORITHM = "RS256"
HMAC_ALGORITHM = "HS256"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF IT NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
        """)
        await db.commit()


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(RSA_PRIV_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(RSA_PUB_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        )
def load_private_key:
    with open(RSA_PRIV_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000
    )
    key = base64.b64encode(kdf.derive(password.encode()))
    return f"{base64.b64encode(salt).decode()}: {key.decode()}"


def verify_password(password, hash_pass):
    salt_b64, key_b64 = hash_pass.split(":")
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations = 100000
    )
    key = base64.b64encode(kdf.derive(password.encode())).decode()
    return key == key_b64

def load_user_by_name(name: str) -> Credentials | None:
    if not os.path.exists(CREDENTIALS_FILE):
        raise  Exception("credentials file missing, should be `credentials.json`")

    with open(CREDENTIALS_FILE, "r") as f:
        users = json.load(f)
    for user in users:
        if user["name"] == name:
            return Credentials.from_dict(user)
    return None
load_user_by_name("ningning").name
#%%
def save_user_token(name: str, token: str):
    with open(CREDENTIALS_FILE, "r") as f:
        users = json.load(f)
    for user in users:
        if user["name"] == name:
            user["tokens"].append(token)
            break
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def generate_jwt(user: Credentials, cenario= "RSA") -> str:
    print('cenario ', cenario)
    if cenario == "RSA":
        with open(RSA_PRIV_KEY_FILE, "r") as f:
            signing_key = f.read()
        algorithm = RSA_ALGORITHM
    else:
        with open(HMAC_KEY_FILE, "r") as f:
            signing_key = f.read()
        algorithm = HMAC_ALGORITHM

    payload = {
        "name": user.name,
        "exp": datetime.datetime.now() + datetime.timedelta(seconds=TOKEN_EXPIRATION_SECONDS),
        "iat": datetime.datetime.now()
    }

    token = jwt.encode(payload, signing_key, algorithm=algorithm)
    return token.decode("utf-8") if isinstance(token, bytes) else token

def api_autenticacao(username: str, password: str, cenario="RSA") -> str | None:
    user = load_user_by_name(username)
    if not user:
        print("User not found.")
        return None
# client should send hashed password but hashing again to ensure no clear password storing 
    hashed_input_pwd = hashlib.sha256(password.encode()).hexdigest() 
    if hashed_input_pwd != user.pwd:
        print("Invalid password.")
        return None
    
    print("User credentials found")

    token = generate_jwt(user, cenario)
    save_user_token(user.name, token)
    return token

def load_key(filename):
    with open(filename, "rb") as f:
        return f.read()



#%%
em_claro = load_user_by_name("ningning")
api_autenticacao(hashlib.sha256(em_claro.name.encode()).hexdigest() , hashlib.sha256(em_claro.pwd.encode()).hexdigest())

test_username = hashlib.sha256(em_claro.name.encode()).hexdigest()
test_password = hashlib.sha256(em_claro.pwd.encode()).hexdigest()

print("\nTeste HMAC :")
hmac_token = api_autenticacao(test_username, test_password, "HMAC")
print("Generated HMAC token:", hmac_token)
hmac_result = api_protegida(hmac_token, "HMAC")
print("API_PROTEGIDA:", hmac_result)

print("\nTeste RSA :")
rsa_token = api_autenticacao(test_username, test_password, "RSA")
print("Generated RSA token:", rsa_token)
rsa_result = api_protegida(rsa_token, "RSA")
print("API_PROTEGIDA:", rsa_result)


print("\nTeste RSA Expired token :")
rsa_token = api_autenticacao(test_username, test_password, "RSA")
print("Generated RSA token:", rsa_token)
import time
time.sleep(TOKEN_EXPIRATION_SECONDS+0.1)
rsa_result = api_protegida(rsa_token, "RSA")
print("API_PROTEGIDA:", rsa_result)
