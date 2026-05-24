import os
import json
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

KEY_DIR = "keys"


def _json_safe(obj):
    """
    Safely convert CP-ABE objects into JSON-serializable form.
    This avoids group.serialize() which is causing your crash.
    """
    try:
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        return str(obj)


_global_state = {
    "pk": None,
    "mk": None
}

def init_system():
    pk, mk = cpabe.setup()

    os.makedirs(KEY_DIR, exist_ok=True)

    # SAFE SERIALIZATION (NOT group.serialize)
    with open(f"{KEY_DIR}/pk.json", "wb") as f:
        f.write(base64.b64encode(pickle.dumps(pk)))

    with open(f"{KEY_DIR}/mk.json", "wb") as f:
        f.write(base64.b64encode(pickle.dumps(mk)))

    _global_state["pk"] = pk
    _global_state["mk"] = mk

    return "keys generated successfully"


def load_keys():
    """
    Reload keys from disk safely.
    (Important for later encrypt/decrypt endpoints)
    """
    with open(f"{KEY_DIR}/pk.json", "r") as f:
        pk = json.load(f)

    with open(f"{KEY_DIR}/mk.json", "r") as f:
        mk = json.load(f)

    return pk, mk


def keygen(attributes):
    sk = cpabe.keygen(_global_state["pk"], _global_state["mk"], attributes)
    return sk


def encrypt(policy, message: bytes):
    """
    Encrypt message under policy.
    """
    pk, _ = load_keys()

    cipher = cpabe.encrypt(pk, policy, message)

    return _json_safe(cipher)


def decrypt(sk, cipher):
    """
    Decrypt ciphertext using secret key.
    """
    message = cpabe.decrypt(sk, cipher)
    return message
