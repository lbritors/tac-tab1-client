import aiohttp
import json
import asyncio
import getpass
import auth_client
from auth_client import load_credential, validate_token, authenticate, register, post_message, get_messages, test_invalid_token


async def try_login(session, username, password, scenario):
    cred = await load_credential(username)
    if cred:
        for token in cred["tokens"]:
            success, result = await validate_token(session, token, scenario)
            if success:
                print("Token válido enconetrado")
                return success, scenario
        print("Nenhum token válido. Autenticando")
        token, scenario, error = await authenticate(session, username, password, scenario)
        if error:
            print(error)
        return token, scenario
    else:
        print("Usuário não registrado. Registrando")
        token, scenario, error = await register(session, username, password, scenario)
        if error:
            print(error)
        return token,scenario

async def main():
    async with aiohttp.ClientSession() as session:
        token = None
        scenario = None
        while True:
            option = input("""Escolha:
            [1] Autenticar,
            [2] Criar mensagem,
            [3] Ver mensagens,
            [4] Testar token,
            [5] Sair
            """)
            if option == "1":
                username = input("Digite o nome de usuário: ")
                password = getpass.getpass("Digite a senha: ")
                scenario_input = input("Escolha o cenário [hmac/rsa]: ").lower()
            if scenario_input not in ["hmac", "rsa"]:
                print("Cenário inválido")
                continue
            token, scenario = await try_login(session, username, password, scenario_input)
            if token:
                print(f"Autenticado! token: {token}")
                print(f"Cenário: {scenario}")

            elif option == "2":
                if not token or not scenario:
                    print("Precisa se autenticar primeiro")
                    continue
                content = input("Digite a mensagem: ")
                success, result = await post_message(session, token, scenario, content)
                if success:
                    print("Mensagem criada com sucesso")
                    print(result)

            elif option == "3":
                if not token or not scenario:
                    print("Autentique-se primeiro")
                    continue
                success, result = await get_messages(session, token, scenario)
                if success:
                    print("Mensagens recuperadass")
                    print(json.dumps(result, indent=2))
                else:
                    print(result)

            elif option == "4":
                invalid_token = input("digite um token")
                scenario_input = input("escolha o cenário 'hmac' ou 'rsa'").lower()
                success, result = await test_invalid_token(session, invalid_token, scenario_input)
                if success:
                    print(result)
                else:
                    print(result)

            elif option == "5":
                break

            else:
                print("Opção inválida")

if __name__ == "__main__":
    asyncio.run(main())