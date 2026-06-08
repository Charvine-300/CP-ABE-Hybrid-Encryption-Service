import base64

from flask import Flask, request, jsonify
from charm.toolbox.pairinggroup import PairingGroup, GT, extract_key
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject

app = Flask(__name__)

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

master_public = None
master_secret = None


# ---------------- SETUP ----------------
@app.route("/setup", methods=["POST"])
def setup():
    global master_public, master_secret
    master_public, master_secret = cpabe.setup()

    return jsonify({"message": "setup successful"})


# ---------------- ENCRYPT ----------------
@app.route("/encrypt", methods=["POST"])
def encrypt():
    global master_public

    data = request.json
    policy = data["policy"]

    # 1. Create symmetric container FIRST
    gt_element = group.random(GT)

    aes_key = extract_key(gt_element)

    cipher = SymmetricCryptoAbstraction(aes_key)
    sym_ct = cipher.encrypt(data["message"].encode())
    sym_ct_b64 = base64.b64encode(sym_ct.encode()).decode()

    # 4. CP-ABE encrypt the GT element
    abe_ct = cpabe.encrypt(master_public, gt_element, policy)

    # 5. Serialize ABE ciphertext
    serialized_abe = objectToBytes(abe_ct, group).decode()

    return jsonify({
        "abe_ct": serialized_abe,
        "sym_ct": sym_ct_b64
    })


# ---------------- DECRYPT ----------------
@app.route("/decrypt", methods=["POST"])
def decrypt():
    global master_public, master_secret

    data = request.json
    private_user_key = data["private_key"]

    # 1. Load bundle
    abe_ct = bytesToObject(data["cipher"]["abe_ct"].encode(), group)
    sym_ct = base64.b64decode(data["cipher"]["sym_ct"])

    # 3. Recover GT element
    gt_element = cpabe.decrypt(master_public, private_user_key, abe_ct)

    if not gt_element:
        return {"error": "access denied"}

    aes_key = extract_key(gt_element)

    cipher = SymmetricCryptoAbstraction(aes_key)
    plaintext = cipher.decrypt(sym_ct)

    return jsonify({
        "message": plaintext.decode()
    })

@app.route("/generate_key", methods=["POST"])
def generate_key():
    global master_public, master_secret

    data = request.json
    attributes = data["attributes"]

    # 1. Generate ABE key
    private_key = cpabe.keygen(master_public, master_secret, attributes)

    # 2. Serialize the key
    serialized_private_key = objectToBytes(private_key, group).decode()

    return jsonify({
        "private_key": serialized_private_key
    })


if __name__ == "__main__":
    app.run(port=5005, debug=True)