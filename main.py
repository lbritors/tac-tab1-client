# %%
import json
import os
import jwt
import datetime
import hashlib

CREDENTIALS_FILE = "credentials.json"
JWT_KEY_FILE = "es256.pem"
KEY_SIZE = 32 # bytes
TOKEN_EXPIRATION_MINUTES = 120

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
#%%

def generate_priv_keys_asym(filename="rsa.pem"):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    private_key = ec.generate_private_key(ec.SECP256R1(), None)
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open(filename, "wb") as f: f.write(pem)
    return 

def generate_hmac_key(filename="hmac.pem", key_size=KEY_SIZE):
    import os
    key = os.urandom(key_size)
    with open(filename, "wb") as f:
        f.write(key)
    print(f"[HMAC KEY ({KEY_SIZE} bytes) in {filename}]")
    return key
generate_hmac_key()
# %%
def generate_ec_jwt_key(filename="es256.pem"):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    key = ec.generate_private_key(ec.SECP256R1())
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

generate_ec_jwt_key()
# %%

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

def generate_jwt(user: Credentials) -> str:
    with open(JWT_KEY_FILE, "r") as f:
        private_key = f.read()

    payload = {
        "name": user.name,
        "exp": datetime.datetime.now() + datetime.timedelta(minutes=TOKEN_EXPIRATION_MINUTES),
        "iat": datetime.datetime.now()
    }

    token = jwt.encode(payload, private_key, algorithm="ES256")

    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def api_autenticacao(username: str, password: str) -> str | None:
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

    token = generate_jwt(user)
    save_user_token(user.name, token)
    return token
#%%
em_claro = load_user_by_name("ningning")
api_autenticacao(hashlib.sha256(em_claro.name.encode()).hexdigest() , hashlib.sha256(em_claro.pwd.encode()).hexdigest())


protegido = load_user_by_name("9e77404183826933ff4ad68a71511f85324835b2c8433dc6b26e614df4290bdf")
api_autenticacao(protegido.name ,  protegido.pwd)
hashlib.sha256(protegido.pwd.encode()).hexdigest()
