from dotenv import load_dotenv
load_dotenv()
import getpass
import hashlib
import json
import os
import aiohttp
import asyncio


from api_server import HMAC_SECRET


API_URL = "https://localhost:5000/messages"
LOGIN_URL = "https://localhost:5001/auth/login"
REGISTER_URL = "https://localhost:5001/auth/register"
CREDENTIALS_FILE = "credentials.json"
DEFAULT_KEY = "64d473a05b66bb916793217fcbcb6c2cddce166523fb54909cd9ba058f1e7b9b"

async def register(session, username, password, scenario="rsa"):
    if scenario not in ["rsa", "hmac"]:
        return None, None, "Cenário inválido. User 'hmac' ou 'rsa'."
    payload = {"username": username, "password": password, "scenario":scenario}
    try:
        print(f"Tentando registrar em: {REGISTER_URL}")
        async with session.post(REGISTER_URL, json=payload, ssl=False) as response:
            if response.status == 201:
                data = await response.json()
                token = data.get("token")
                scenario = data.get("scenario")
                if token:
                    await save_credentials(username, password, token, scenario)
                    return token, scenario, None
                return None, None, "Token não encontrado na resposta!!"
            return None, None, f"erro ao registrar: {response.status} - {await response.text()}"
    except aiohttp.ClientError as e:
        return None, None, f"Erro ao conectar ao servidor {e}"
    except Exception as e:
        return None, None, f"Erro inesperado no registro: {e}"


async def authenticate(session, username, password, scenario="rsa"):
    if scenario not in ["hmac", "rsa"]:
        return None, None, "Cenário inválido. Use 'hmac' ou 'rsa'."

    payload = {
        "username": username,
        "password": password,
        "scenario": scenario
    }

    try:
        async with session.post(LOGIN_URL, json=payload, ssl=False) as response:
            status = response.status
            try:
                data = await response.json()
            except aiohttp.ContentTypeError:
                text = await response.text()
                return None, None, f"Erro resposta inválida: status- {status} - texto: {text}"
            if status == 200:
                token = data.get("token")
                scenario = data.get("scenario")
                if token and scenario:
                    await save_credentials(username, password, token, scenario)
                    return token,scenario, None
                return None, None, "Token não encontrado na resposta"
            return None, None, f"Erro na autenticação: {status} - {data.get('erro', await response.text())}"
    except aiohttp.ClientError as error:
        return None, None, f"Erro ao conectar ao servidor: {error}"
    except Exception as e:
        return None, None, f"Erro inesperado na autenticação: {e}"


async def create_message(session, token, scenario, content, api_url = API_URL):
    if scenario not in ["hmac", "rsa"]:
        return False, "Cenário inválido."
    payload = {"content": content}
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Auth-Scenario": scenario
    }

    try:
        async with session.post(api_url, json=payload, headers=headers, ssl=False) as response:
            if response.status == 201:
                res = await response.json()
                print("Mensagem criada com sucesso!\n")
                print(res)
                return  True, res
            else:
                text = await response.text()
                print(f"Erro ao criar mensagem: {response.status} - {text}")
                return False, f"{response.status} - {text}"
    except aiohttp.ClientError as e:
        return False, f"Erro ao conectar à API: {e}"


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
                return True, await response.json()
            return False, f"Erro ao recuperar mensagens: {response.status} - {await response.text()}"
    except aiohttp.ClientError as e:
        return False, f"Erro ao conectar à API: {e}"


async def validate_token(session, token, scenario):
    success, result = await get_messages(session, token, scenario)
    return success, result

async def load_credentials(username):
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            credentials = json.load(f)
            if not isinstance(credentials, list):
                print(f"Erro: credentials.json não é uma lista: {credentials}")
                return None
            for cred in credentials:
                if not isinstance(cred, dict):
                    print(f"Erro: entrada inválida em credentials.json: {cred}")
                    continue
                if cred["username"] == username:
                    return cred
        return None
    except FileNotFoundError:
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump([], f)
        return None
    except json.JSONDecodeError as e:
        print(f"Erro: credentials.json inválido {e}")
        return None
    except Exception as e:
        print(f"Erro em load_credentials: {e}")
        return None


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
                if not isinstance(credentials, list):
                    credentials = []
        except (FileNotFoundError, json.JSONDecodeError):
            credentials = []

        user = False
        for cred in credentials:
            if not isinstance(cred, dict):
                continue
            if cred.get("username") == username:
                if token and token not in cred.get("tokens", []):
                    cred["tokens"] = cred.get("tokens", []) +  [token]
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
