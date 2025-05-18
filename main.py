# %%
import json
import os
import jwt
import datetime
import hashlib
from jwt import InvalidTokenError, ExpiredSignatureError, InvalidSignatureError

KEY_SIZE = 32 # bytes
TOKEN_EXPIRATION_MINUTES = 120
CREDENTIALS_FILE = "credentials.json"
HMAC_KEY_FILE = "hmac.pem"
RSA_PUB_KEY_FILE = "rsa_public.pem" 
RSA_PRIV_KEY_FILE = "rsa_private.pem" 
RSA_ALGORITHM = "RS256"
HMAC_ALGORITHM = "HS256"

class Credentials:
    def __init__(self, id, name, pwd, key, tokens):
        self.id = id
        self.name = name
        self.pwd = pwd
        self.key = key
        self.tokens = tokens

    @staticmethod
    def from_dict(d):
        return Credentials(d["id"], d["name"], d["pwd"], d["key"], d.get("tokens", []))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "pwd": self.pwd,
            "key": self.key,
            "tokens": self.tokens
        }

def load_user_by_name(name: str) -> Credentials | None:
    if not os.path.exists(CREDENTIALS_FILE):
        raise  Exception("credentials file missing, should be `credentials.json`")

    with open(CREDENTIALS_FILE, "r") as f:
        users = json.load(f)
    for user in users:
        if user["name"] == name:
            return Credentials.from_dict(user)
    return None
load_user_by_name("ningning").name
#%%
def save_user_token(name: str, token: str):
    with open(CREDENTIALS_FILE, "r") as f:
        users = json.load(f)
    for user in users:
        if user["name"] == name:
            user["tokens"].append(token)
            break
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def generate_jwt(user: Credentials, cenario= "RSA") -> str:
    print('cenario ', cenario)
    if cenario == "RSA":
        with open(RSA_PRIV_KEY_FILE, "r") as f:
            signing_key = f.read()
        algorithm = "RS256"
    else:
        with open(HMAC_KEY_FILE, "r") as f:
            signing_key = f.read()
        signing_key = HMAC_KEY_FILE
        algorithm = "HS256"

    payload = {
        "name": user.name,
        "expiration": str(datetime.datetime.now() + datetime.timedelta(minutes=TOKEN_EXPIRATION_MINUTES)),
        "issued": str(datetime.datetime.now())
    }

    token = jwt.encode(payload, signing_key, algorithm=algorithm)
    return token.decode("utf-8") if isinstance(token, bytes) else token

def api_autenticacao(username: str, password: str, cenario="RSA") -> str | None:
    user = load_user_by_name(username)
    if not user:
        print("User not found.")
        return None
# client should send hashed password but hashing again to ensure no clear password storing 
    hashed_input_pwd = hashlib.sha256(password.encode()).hexdigest() 
    if hashed_input_pwd != user.pwd:
        print("Invalid password.")
        return None
    
    print("User credentials found")
    if cenario == "RSA":
        token = generate_jwt(user, "RSA")
    else:
        token = generate_jwt(user, "HMAC")
    save_user_token(user.name, token)
    return token

def load_key(filename):
    with open(filename, "rb") as f:
        return f.read()

def api_protegida(token: str, cenario="RSA") -> str:
    try:
        if cenario == "RSA":
            key = load_key(HMAC_KEY_FILE)
            algorithm = HMAC_ALGORITHM
        else:
            key = load_key(RSA_PUB_KEY_FILE)
            algorithm = RSA_ALGORITHM

        # Decode and verify token
        payload = jwt.decode(token, key, algorithms=[algorithm])
        username = payload.get("name")

        return f"[ACESSO LIBERADO] Olá, {username}! Aqui estão os dados protegidos."

    except ExpiredSignatureError:
        return "[ERRO] Token expirado."
    except InvalidSignatureError:
        return "[ERRO] Assinatura inválida."
    except InvalidTokenError as e:
        return f"[ERRO] Token inválido: {str(e)}"

#%%
em_claro = load_user_by_name("ningning")
api_autenticacao(hashlib.sha256(em_claro.name.encode()).hexdigest() , hashlib.sha256(em_claro.pwd.encode()).hexdigest())

test_username = hashlib.sha256(em_claro.name.encode()).hexdigest()
test_password = hashlib.sha256(em_claro.pwd.encode()).hexdigest()
# Scenario 1: HMAC
print("\nTesting HMAC scenario:")
hmac_token = api_autenticacao(test_username, test_password, "HMAC")
print("Generated HMAC token:", hmac_token)
hmac_result = api_protegida(hmac_token, "HMAC")
print("Protected API result:", hmac_result)

# Scenario 2: RSA
print("\nTesting RSA scenario:")
rsa_token = api_autenticacao(test_username, test_password, "RSA")
print("Generated RSA token:", rsa_token)
rsa_result = api_protegida(rsa_token, "RSA")
print("Protected API result:", rsa_result)

# Test invalid token
print("\nTesting invalid token:")
invalid_token = "invalid.token.here"
invalid_result = api_protegida(invalid_token, "RSA")
print("Invalid token result:", invalid_result)




protegido = load_user_by_name("9e77404183826933ff4ad68a71511f85324835b2c8433dc6b26e614df4290bdf")
api_autenticacao(protegido.name ,  protegido.pwd)
hashlib.sha256(protegido.pwd.encode()).hexdigest()
