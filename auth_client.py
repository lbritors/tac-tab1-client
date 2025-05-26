import getpass
import hashlib
import json
import os

import aiohttp
import asyncio

from dotenv import load_dotenv

from api_server import HMAC_SECRET

load_dotenv()

API_URL = os.getenv("API_URL")
LOGIN_URL = os.getenv("LOGIN_URL")
REGISTER_URL = os.getenv("REGISTER_URL")
CREDENTIALS_FILE = "credentials.json"
DEFAULT_KEY = "64d473a05b66bb916793217fcbcb6c2cddce166523fb54909cd9ba058f1e7b9b"

async def register(session, username, password, scenario="rsa"):
    auth_url = REGISTER_URL
    if scenario not in ["rsa", "hmac"]:
        return None, None, "Cenário inválido. User 'hmac' ou 'rsa'."
    payload = {"username": username, "password": password, "scenario":scenario}
    try:
        async with session.post(auth_url, json=payload, ssl=False) as response:
            if response.status == 201:
                data = await response.json()
                token = data.get("token")
                scenario = data.get("scenario")
                if token:
                    await save_credential(username, password, token, scenario)
                    return token, scenario, None
                return None, None, "Token não encontrado na resposta!!"
    except aiohttp.ClientError as e:
        return None, None, f"Erro ao conectar ao servidor {e}"


async def authenticate(session, username, password, scenario="rsa"):
    auth_url = LOGIN_URL
    if scenario not in ["hmac", "rsa"]:
        return None, None, "Cenário inválido. Use 'hmac' ou 'rsa'."

    data = {
        "username": username,
        "password": password,
        "scenario": scenario
    }

    try:
        async with session.post(auth_url, json=data, ssl=False) as response:
            if response.status == 200:
                res = await response.json()
                token = res.get("token")
                scenario = res.get("scenario")
                if token:
                    await save_credential(username, password, token, scenario)
                    return token,scenario, None
                return None, None, "Token não encontrado na resposta"
            return None, None, f"Erro na autenticação: {response.status} - {await response.text()}"
    except aiohttp.ClientError as error:
        return None, None, f"Erro ao conectar ao servidor: {error}"


async def post_message(session, token, scenario, content, api_url = API_URL):
    if scenario not in ["hmac", "rsa"]:
        return False, "Cenário inválido."
    data = {"content": content}
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Auth-Scenario": scenario
    }

    try:
        async with session.post(api_url, json=data, headers=headers, ssl=False) as response:
            if response.status == 201:
                res = await response.json()
                print("Mensagem criada com sucesso!\n")
                print(res)
            else:
                text = await response.text()
                print(f"Erro ao criar mensagem: {response.status} - {text}")
    except aiohttp.ClientError as error:
        print(f"Erro ao conectar à API: {error}")

async def get_messages(session, token, scenario, api_url = API_URL):
    if scenario not in ["hmac", "rsa"]:
        return False, "Cenário inválido."
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Auth-Scenario": scenario
    }
    try:
        async with session.get(api_url, headers=headers, ssl=False) as response:
            if response.status == 200:
                messages = json.dumps(await response.json(), indent=2)
                print("Mensagens recuperadoas", messages)
            else:
                text = await response.text()
                print(f"Erro ao recuperar mensagens : {response.status} - {text}")
    except aiohttp.ClientError as e:
        print(f"Erro ao conectar à API: {e}")

async def validate_token(session, token, scenario):
    success, result = await get_messages(session, token, scenario)
    return success, result

async def load_credential(username):
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            credentials = json.load(f)
            for cred in credentials:
                if cred["username"] == username:
                    return cred
        return None
    except (FileNotFoundError, json.JSONDecodeError):
        return "Erro: arquivo não encontrado"

async def test_invalid_token(session, token, scenario, api_url=API_URL):
    if scenario not in ["hmac", "rsa"]:
        return False, "Cenário inválido"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Auth-Scenario": scenario
    }
    try:
        async with session.get(api_url, headers=headers, ssl=False) as response:
            return True, f"Resultado: {response.status} - {await response.text()}"
    except aiohttp.ClientError as e:
        return False, f"Erro ao conectar a API: {e}"


async def save_credentials(username, password, token, scenario):
    try:
        try:
            with open(CREDENTIALS_FILE, "r") as f:
                credentials = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            credentials = []

        user = False
        for cred in credentials:
            if cred["username"] == username:
                if token and token not in cred["tokens"]:
                    cred["tokens"].append(token)
                cred["pwd"] = password
                user = True
                break

        if not user:
            user_id = hashlib.sha256(username.encode()).hexdigest()
            credentials.append({
                "id": user_id,
                "username": username,
                "pwd": password,
                "Key": DEFAULT_KEY,
                "tokens": [token] if token else []
            })

        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(credentials, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar as credenciais: {e}")
