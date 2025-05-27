# %%
from dotenv import load_dotenv
load_dotenv()
import asyncio
import json
import os
import jwt
import datetime
import ssl
import base64
import logging
from aiohttp import web
import aiosqlite
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)



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
REGISTER_URL = "https://localhost:5001/auth/register"
LOGIN_URL = "https://localhost:5001/auth/login"


async def init_db():
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            );
            """)
            await db.commit()
            logger.info(f"AUTH db inicializado!")
    except aiosqlite.Error as e:
        logger.error(f"Erro ao inicializar auth_db {e}")
        raise


def generate_rsa_keys():
    try:
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
        logger.info("RSA key gerada")
    except Exception as e:
        logger.error(f"Erro ao gerar rsa key {e}")
        raise


def load_private_key():
    try:
        with open(RSA_PRIV_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        logger.error(f"Erro ao pegar chave privada {e}")
        raise


def hash_password(password):
    try:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=100000
        )
        key = base64.b64encode(kdf.derive(password.encode()))
        return f"{base64.b64encode(salt).decode()}: {key.decode()}"
    except Exception as e:
        logger.error(f"Erro ao hashear senha: {e}")
        raise


async def generate_token(username, scenario):
    try:
        now_utc = datetime.datetime.now(datetime.UTC)
        data = {
            "exp":now_utc + datetime.timedelta(seconds=TOKEN_EXPIRATION_SECONDS),
            "sub": username,
            "iac": now_utc.isoformat()
        }
        if scenario == "hmac":
            if not HMAC_SECRET:
                raise ValueError("HMAC_SECRET is not set")
            token = jwt.encode(data, HMAC_SECRET, algorithm="HS256")
        else:
            private_key = load_private_key()
            token = jwt.encode(data, private_key, algorithm="RS256")
        logger.info(f"Token gerado para o usuário {username} com cenário {scenario}")
        return token
    except Exception as e:
        logger.error(f"Erro ao gerar token: {e}")
        raise


def verify_password(password, hash_pass):
    try:
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
    except Exception as e:
        logger.error(f"Erro ao verificar senha: {e}")
        return False

async def handle_register(request):
    logger.debug(f"Received register request: {request}")
    if request.method != "POST":
        return web.json_response({"erro": "Método não permitido"}, status=405)
    try:
        data = await request.json()
    except json.JSONDecodeError:
        logger.error("Invalid JSON in register request")
        return web.json_response({"erro": "JSON inválido"}, status=400)
    username = data.get("username")
    password = data.get("password")
    scenario = data.get("scenario", "rsa").lower()
    if scenario not in ["hmac", "rsa"]:
        logger.error(f"Invalid scenario: {scenario}")
        return web.json_response({"erro": "Cenário inválido (use 'hmac' ou 'rsa')"}, status=400)
    if not username or not password:
        logger.error("Missing username or password")
        return web.json_response({"erro": "Credenciais inválidas, faltam dados"}, status=400)
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                if await cursor.fetchone():
                    logger.warning(f"User {username} already exists")
                    return web.json_response({"erro": "Usuário já existe"}, status=409)
            password_hash = hash_password(password)
            await db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            await db.commit()
            token = await generate_token(username, scenario)
            response_data = {
                "message": "Usuário registrado com sucesso",
                "token": token,
                "scenario": scenario
            }
            logger.debug(f"Sending register response: {response_data}")
            return web.json_response(response_data, status=201)
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return web.json_response({"erro": f"Erro interno: {str(e)}"}, status=500)


async def handle_login(request):
    logger.debug(f"Received login request: {request}")
    if request.method != "POST":
        return web.json_response({"erro": "Método não permitido"}, status=405)
    try:
        data = await request.json()
    except json.JSONDecodeError:
        logger.error("Invalid JSON in login request")
        return web.json_response({"erro": "JSON inválido"}, status=400)
    username = data.get("username")
    password = data.get("password")
    scenario = data.get("scenario", "rsa").lower()
    if scenario not in ["hmac", "rsa"]:
        logger.error(f"Invalid scenario: {scenario}")
        return web.json_response({"erro": "Cenário inválido"}, status=400)
    if not username or not password:
        logger.error("Missing username or password")
        return web.json_response({"erro": "Credenciais inválidas"}, status=400)
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            async with db.execute("SELECT password_hash FROM users WHERE username = ?", (username,)) as cursor:
                result = await cursor.fetchone()
                if result and verify_password(password, result[0]):
                    token = await generate_token(username, scenario)
                    logger.info(f"User {username} logged in successfully")
                    return web.json_response({"token": token, "scenario": scenario}, status=200)
                logger.warning(f"Invalid credentials for user {username}")
                return web.json_response({"erro": "Credenciais inválidas"}, status=401)
        except Exception as e:
            logger.error(f"Login error: {e}")
            return web.json_response({"erro": f"Erro interno: {str(e)}"}, status=500)

async def run_server():
    await init_db()
    if not (os.path.exists(RSA_PRIV_KEY_FILE) and os.path.exists(RSA_PUB_KEY_FILE)):
        generate_rsa_keys()

    app = web.Application()
    app.router.add_post("/auth/register", handle_register)
    app.router.add_post("/auth/login" ,handle_login)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=CERT_KEY_FILE)

    run = web.AppRunner(app)
    await run.setup()
    site = web.TCPSite(run, "0.0.0.0", PORT, ssl_context=ssl_context)
    await site.start()

    print(f"Api de autenticação rodando na porta {PORT}")
    print(REGISTER_URL)
    await asyncio.Event().wait()


if __name__=="__main__":
    asyncio.run(run_server())

