import getpass
import aiohttp
import asyncio

async def authenticate():

    auth_url = ""
    username = input("Digite seu login: ")
    password = getpass.getpass("Digite sua senha: ")
    scenario = input("Escolha o a forma de autenticação [hmac/rsa]: ").lower()

    data = {
        "username": username,
        "password": password
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(auth_url, json=data) as response:
                if response.status == 200:
                    res = await response.json()
                    token = res.get("token")
                    if token:
                        print("Autenticação deu certo!")
                        print("Token: ", token)
                    else:
                        print("Autenticação não deu certo!")
                else:
                    print(f"Erro na autenticação: {response.status} - {await response.text()} ")
    except aiohttp.ClientError as error:
        print(f"Erro ao conectar ao servidor: {error}")

async def main():
    await authenticate()


if __name__=="__main__":
    asyncio.run(main())
