import os
import ssl

from dotenv import load_dotenv

import asyncio
import json
import jwt
import datetime
import urllib.parse
from aiohttp import web
import aiosqlite
from cryptography.hazmat.primitives import serialization

from auth_server import DB_PATH, RSA_PUB_KEY_FILE

PORT = 5000
API_DB_PATH = "database.db"
PUB_KEY_FILE = "rsa_public.pem"
HMAC_KEY_FILE = "hmac.pem"
HMAC_SECRET = os.getenv("HMAC_SECRET")
CERT_FILE = "./public_certificate.pem"
CERT_KEY_FILE = "./private_certif_key.pem"
load_dotenv()

async def init_db():
    async with aiosqlite.connect(API_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)
        await db.commit()

def load_public_key():
    with open(PUB_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def validate_token(token, scenario = "hmac"):
    try:
        if scenario == "hmac":
            payload= jwt.decode(token, HMAC_SECRET, algorithms = ["HS256"])
        else:
            public_key = load_public_key()
            payload = jwt.decode(token, public_key, algorithms = ["HS256"])
        return payload.get("sub"), None
    except jwt.ExpiredSignatureError:
        return None, "Token expirado"
    except jwt.InvalidTokenError:
        return None, "Token inválido"

def get_token(request):
    auth_header = request.header.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    return None


async def handle_post(request):
    token = get_token(request)
    scenario = request.headers.get("X-Auth-Scenario", "hmac")
    if scenario not in ["hmac", "rsa"]:
        return web.json_response({"error": "Cenário inválido (use hmac ou rsa)"}, status=400)
    if not token:
        return web.json_response({"error": "Token é necessário"}, status=401)

    user_id, error = validate_token(token, scenario)
    if not user_id:
        return web.json_response({"error": error or "Token inválido"}, status=401)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "JSON inválido"}, status=400)

    content = data.get("content")
    if not isinstance(content,str) or not content.strip():
        return web.json_response({"error": "Conteúdo deve ser uma string não vazia"}, status=400)

    async with aiosqlite.connect(API_DB_PATH) as db:
        try:
            async with db.execute("""
                INSERT INTO messages (user_id, content) VALUES(?, ?)
            """, (user_id, content)) as cursor:
                await db.commit()
                message_id = cursor.lastrowid
            return web.json_response({
                "id": message_id,
                "user_id": user_id,
                "content": content,
                "created_at": datetime.datetime.utcnow().isoformat()
            }, status=201)
        except aiosqlite.Error as e:
            return web.json_response({"error": f"Erro no banco de dados: {str(e)}"}, status=500)


async def handle_get(request):
    token = get_token(request)
    scenario = request.headers.get("X-Auth-Scenario", "hmac")
    if scenario not in ["rsa", "hmac"]:
        return web.json_response({"error": "Cenário inválido (user hmac ou rsa)"}, status=400)
    if not token:
        return web.json_response({"error": "Token é necessário"},status=401)
    user_id, error = validate_token(token, scenario)
    if not user_id:
        return web.json_response({"error": error or "Token inválido"}, status=401)

    async with aiosqlite.connect(API_DB_PATH) as db:
        try:
            async with db.execute("""
                SELECT * FROM messages WHERE user_id = ?
            """, (user_id,)) as cursor:
                messages = [
                    {
                        "id" : row[0],
                        "user_id" : row[1],
                        "content" : row[2],
                        "created_at" : row[3]
                    } async for row in cursor
                ]
            return web.json_response({"messages": messages}, status=200)
        except aiosqlite.Error as e:
            return web.json_response({"error": f"Erro no banco de dados: {str(e)}"}, status=500)


async def run_server():
    await init_db()
    app = web.Application()
    app.router.add_get("/messages", handle_get)
    app.router.add_post("/messages", handle_post)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=CERT_KEY_FILE)

    run = web.AppRunner(app)
    await run.setup()
    site = web.TCPSite(run, "0.0.0.0", PORT, ssl_context=ssl_context)
    await site.start()

    print(f"Api protegida rodando na em localhost {PORT}")
    await asyncio.Event.wait()


if __name__=="__main__":
    asyncio.run(run_server())