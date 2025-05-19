import os

from dotenv import load_dotenv

import asyncio
import json
import jwt
import datetime
import urllib.parse
from aiohttp import web
import aiosqlite
import requests
from cryptography.hazmat.primitives import serialization

from auth_server import DB_PATH, RSA_PUB_KEY_FILE

PORT = 5000
API_DB_PATH = "database.db"
PUB_KEY_FILE = "rsa_public.pem"
CERT_FILE = "cert.pem"
HMAC_KEY_FILE = "hmac.pem"
HMAC_SECRET = os.getenv("HMAC_SECRET")
load_dotenv()

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
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
