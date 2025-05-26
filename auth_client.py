import getpass
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
