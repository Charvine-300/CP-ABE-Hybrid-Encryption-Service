# CP-ABE Hybrid Encryption Service

A Flask-based hybrid cryptographic system that combines Ciphertext-Policy Attribute-Based Encryption (CP-ABE) with AES symmetric encryption. It enables fine-grained, policy-based access control over encrypted data while efficiently handling large payloads using symmetric cryptography.

## 🔐 Overview

This system implements a hybrid encryption model:

- A random element in the target group \( G_T \) is generated
- The \( G_T \) element is hashed using `extract_key()` to derive an AES key
- AES encrypts the actual plaintext data
- CP-ABE encrypts the \( G_T \) element under a policy
- Only users whose attributes satisfy the policy can recover the AES key and decrypt the data

This ensures secure, policy-controlled access to encrypted data.

## ⚙️ Architecture

Plaintext Message
↓
AES Encryption (SymmetricCryptoAbstraction)
↓
Encrypted Payload (sym_ct)

Random GT Element
↓
extract_key(GT) → AES Key
↓
CP-ABE Encryption (Policy-Based)
↓
ABE Ciphertext (abe_ct)

Final Output:
{
"abe_ct": "...",
"sym_ct": "..."
}

## 🧰 Technologies Used

- Python 3.10+
- Flask
- Charm-Crypto (`charm-crypto`)
- CP-ABE (BSW07 scheme)
- Pairing-based cryptography (SS512 curve)
- AES (via Charm SymmetricCryptoAbstraction)
- Base64 encoding for safe transport

## 📦 Features

- Hybrid encryption (CP-ABE + AES)
- Policy-based access control
- Secure key encapsulation using \( G_T \)
- Efficient symmetric encryption for payloads
- REST API for encryption and decryption
- JSON-based request/response format


## 📁 Project Structure

```bash
cpabe-hybrid-encryption-service/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── keys/              # excluded from version control (sensitive keys)
```

## 🔧 Prerequisites

Ensure you have the following installed:

- Python 3.10+
- pip
- Virtual environment (recommended)

Install dependencies:

```bash
pip install flask charm-crypto
````

## 🚀 How to Run

### 1. Clone repository

```bash
git clone https://github.com/your-username/cpabe-hybrid-encryption-service.git
cd cpabe-hybrid-encryption-service
```

### 2. Create virtual environment (optional)

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start server

```bash
python app.py
```

Server runs at:

```
http://127.0.0.1:5005
```

## 🔑 API Endpoints

### 🟢 Setup Keys

**POST** `/setup`

Initializes CP-ABE master keys.

```bash
curl -X POST http://127.0.0.1:5005/setup
```

### 🔒 Encrypt Data

**POST** `/encrypt`

Encrypts a message using AES + CP-ABE policy wrapping.

#### Request

```json
{
  "policy": "(HR or Manager)",
  "message": "Hello World"
}
```

#### Response

```json
{
  "abe_ct": "<serialized-cpabe-ciphertext>",
  "sym_ct": "<base64-aes-ciphertext>"
}
```

### 🔓 Decrypt Data

**POST** `/decrypt`

Decrypts ciphertext using attribute-based keys.

#### Request

```json
{
  "attributes": ["HR"],
  "cipher": {
    "abe_ct": "<cpabe-ciphertext>",
    "sym_ct": "<aes-ciphertext>"
  }
}
```

#### Response

```json
{
  "message": "Hello World"
}
```

## 🧪 Example Workflow

### Step 1: Setup

```bash
curl -X POST http://127.0.0.1:5005/setup
```

### Step 2: Encrypt

```bash
curl -X POST http://127.0.0.1:5005/encrypt \
-H "Content-Type: application/json" \
-d '{
  "policy": "(HR or Manager)",
  "message": "Hello World"
}'
```

### Step 3: Decrypt

```bash
curl -X POST http://127.0.0.1:5005/decrypt \
-H "Content-Type: application/json" \
-d '{
  "attributes": ["HR"],
  "cipher": {
    "abe_ct": "...",
    "sym_ct": "..."
  }
}'
```

## 🔐 Security Notes

* The `keys/` directory is excluded from version control via `.gitignore`
* This project is intended for educational and research purposes
* Not hardened for production cryptographic security use cases

## 👨‍💻 Author

Chidera Ezenwekwe


## ⚠️ Usage Disclaimer

This project is for learning, experimentation, and research. It is not intended for production deployment without further security auditing and cryptographic hardening.