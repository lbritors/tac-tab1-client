# %%
import asyncio
import json
import os
import time

import jwt
import datetime
from datetime import timezone, timedelta
import ssl
import base64
from aiohttp import web
import aiosqlite
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from dotenv import load_dotenv



load_dotenv()

PORT = 5001
KEY_SIZE = 32 # bytes
TOKEN_EXPIRATION_SECONDS = 3600 #1 hora
DB_PATH = "auth_database.db"
HMAC_KEY_FILE = "./hmac.pem"
CREDENTIALS_FILE = "credentials.json"
RSA_PUB_KEY_FILE = "rsa_public.pem"
RSA_PRIV_KEY_FILE = "rsa_private.pem"
RSA_ALGORITHM = "RS256"
HMAC_ALGORITHM = "HS256"
HMAC_SECRET = os.getenv("HMAC_SECRET")
CERT_FILE = "./public_certificate.pem"
CERT_KEY_FILE = "./private_certif_key.pem"


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
def load_private_key():
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

async def generate_token(username, scenario):
    data = {
        "exp": datetime.datetime.now() + datetime.timedelta(seconds=TOKEN_EXPIRATION_SECONDS),
        "sub": username,
        "iac": datetime.datetime.now()
    }
    if scenario == "hmac":
        token = jwt.encode(data, HMAC_SECRET, algorithm="HS256")
    else:
        private_key = load_private_key()
        token = jwt.encode(data, private_key, algorithm="RS256")
    return token

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

async def handle_register(request):
    if request.method == "POST":
        try:
            data = await request.json()
        except json.JSONDecodeError as e:
            return web.json_response({"erro":"JSON inválido"}, status=400)

        username = data.get("username")
        password = data.get("password")
        scenario = data.get("scenario")
        if scenario not in ["hmac", "rsa"]:
            return web.json_response({"erro": "cenário inválido (use 'hmac' ou 'rsa'"}, status=400)
        if not username or not password:
            return web.json_response({"erro": "credenciais inválidas, faltam dados"}, status=400)
        async with aiosqlite.connect(DB_PATH) as db:
            try:
               async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                   if await cursor.fetchone():
                       return web.json_response({"erro": "usuário já existe"}, status=409)
                   password_hash = hash_password(password)
                   await db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
                   await db.commit()
                   token = await generate_token(username, scenario)
                   return web.json_response({"message": "Usuário registrado com sucesso", "token": token, "scenario": scenario}, status=201)
            except aiosqlite.Error as e:
                return web.json_response({"erro": f"erro no banco de dados: {str(e)}"}, status=500)
    return web.json_response({"erro": "método não permitido"},status=405)

async def handle_login(request):
    if request.method == "POST":
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "JSON inválido"}, status=400)

        username = data.get("username")
        password = data.get("password")
        scenario = data.get("scenario", "rsa").lower()

        if scenario not in ["hmac", "rsa"]:
            return web.json_response({"error": "Cenário inválido"}, status=400)
        if not username or not password:
            return web.json_response({"error": "Autenticação inválida"}, status=400)
        async with aiosqlite.connect(DB_PATH) as db:
            try:
                async with db.execute("""
                    SELECT password_hash FROM users WHERE username = ?
                """, (username,)) as cursor:
                    result = await cursor.fetchone()
                    if result and verify_password(result[0], password):
                        token = await generate_token(username, scenario)
                        return web.json_response({"token": token, "cenário":scenario}, status = 200)
                    else:
                        return web.json_response({"erro": "credenciais inválidas"}, status=401)
            except aiosqlite.Error as e:
                return web.json_response({"error": f"Não foi possível conectar com o banco de dados: {str(e)}"}, status=500)
    return web.json_response({"erro":"método POST não permitido"}, status=405)

async def run_server():
    await init_db()
    if not (os.path.exists(RSA_PRIV_KEY_FILE) and os.path.exists(RSA_PUB_KEY_FILE)):
        generate_rsa_keys()

    app = web.Application()
    app.router.add_post("/auth_register", handle_register)
    app.router.add_get("/auth_login", handle_login())

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=CERT_KEY_FILE)

    run = web.AppRunner(app)
    await run.setup()
    site = web.TCPSite(run, "0.0.0.0", PORT, ssl_context=ssl_context)
    await site.start()

    print(f"Api de autenticação rodando na porta {PORT}")
    await asyncio.Event().wait()



async def main():
    print(HMAC_SECRET)


if __name__=="__main__":
    asyncio.run(main())
