import aiohttp
import json
import asyncio
import getpass
from auth_client import load_credentials, validate_token, authenticate, register, create_message, get_messages, test_invalid_token

async def try_login(session, username, password, scenario):
    cred = await load_credentials(username)
    if cred is None:
        print("Usuário não encontrado no credentials.json. Registrando.")
        result = await register(session, username, password, scenario)
        if result is None:
            print("Erro: register retornou None inesperadamente.")
            return None, None
        token, scenario, error = result
        if error:
            print(f"Erro ao registrar: {error}")
        return token, scenario
    if not isinstance(cred, dict):
        print(f"Erro: cred não é um dicionário: {cred}, tipo: {type(cred)}")
        return None, None
    tokens = cred.get("tokens", [])
    if not isinstance(tokens, list):
        print(f"Erro: tokens não é uma lista: {tokens}, tipo: {type(tokens)}")
        return None, None
    for token in tokens:
        if token:
            success, result = await validate_token(session, token, scenario)
            if success:
                print("Token válido encontrado!")
                return token, scenario
    print("Nenhum token válido. Autenticando.")
    result = await authenticate(session, username, password, scenario)
    if result is None:
        print("Erro: authenticate retornou None inesperadamente.")
        return None, None
    token, scenario, error = result
    if error:
        print(f"Erro na autenticação: {error}")
    return token, scenario

async def main():
    async with aiohttp.ClientSession() as session:
        token = None
        scenario = None
        while True:
            option = input("""Escolha:
            [1] Autenticar,
            [2] Criar mensagem,
            [3] Ver mensagens,
            [4] Testar token inválido,
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
                    print(f"Autenticado! Token: {token}")
                    print(f"Cenário: {scenario}")
                else:
                    print("Falha na autenticação.")
            elif option == "2":
                if not token or not scenario:
                    print("Precisa se autenticar primeiro")
                    continue
                print(f"Token ao criar mensagem: {token}") # Adicione esta linha
                content = input("Digite a mensagem: ")
                success, result = await create_message(session, token, scenario, content)
                if success:
                    print("Mensagem criada com sucesso")
                    print(result)
                else:
                    print(f"Erro: {result}")
            elif option == "3":
                if not token or not scenario:
                    print("Autentique-se primeiro")
                    continue
                success, result = await get_messages(session, token, scenario)
                if success:
                    print("Mensagens recuperadas")
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Erro: {result}")
            elif option == "4":
                invalid_token = input("Digite um token inválido: ")
                scenario_input = input("Escolha o cenário [hmac/rsa]: ").lower()
                success, result = await test_invalid_token(session, invalid_token, scenario_input)
                if success:
                    print(result)
                else:
                    print(f"Erro: {result}")
            elif option == "5":
                break
            else:
                print("Opção inválida")

if __name__ == "__main__":
    asyncio.run(main())