import getpass
import json
import os

import aiohttp
import asyncio

from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL")
AUTH_URL = os.getenv("AUTH_URL")

async def authenticate(session):

    username = input("Digite seu login: ")
    password = getpass.getpass("Digite sua senha: ")
    scenario = input("Escolha o a forma de autenticação [hmac/rsa]: ").lower()
    if scenario not in ["rsa", "hmac"]:
        print("Cenário inválido. User 'hmac' ou 'rsa'.")
        return None,None
    data = {
        "username": username,
        "password": password,
        "scenario": scenario
    }

    try:
        async with session.post(AUTH_URL, json=data, ssl=False) as response:
            if response.status == 200:
                res = await response.json()
                token = res.get("token")
                scenario = res.get("scenario")
                if token:
                    print("Autenticação deu certo!")
                    return token,scenario
                else:
                    print("Autenticação não deu certo!Token não encontrado na resposta")
            else:
                text = await response.text()
                print(f"Erro na autenticação: {response.status} - {text} ")
    except aiohttp.ClientError as error:
        print(f"Erro ao conectar ao servidor: {error}")
    return None, None


async def post_message(session, token, scenario, api_url = API_URL):
    content = input("Digite a mensagem confidencial: ")
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



async def main():
    await authenticate()


if __name__=="__main__":
    asyncio.run(main())
