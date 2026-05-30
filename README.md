# 🔐 SecureVault — Encrypted File Transfer & Secure Storage

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://www.python.org/)
[![AES](https://img.shields.io/badge/Encryption-AES--256--GCM-red)]()
[![HMAC](https://img.shields.io/badge/Integrity-HMAC--SHA256-orange)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

> **SecureVault** implements encrypted file upload/download between a Python client and server using AES-256-GCM encryption, per-chunk HMAC-SHA256 integrity checks, and a zero-knowledge server design — files are never decrypted server-side.

> Built during Week 3 internship at **Syntecxhub**.

---

## ✨ Features

- 🔐 **AES-256-GCM** — authenticated encryption per chunk (detects tampering)
- 🔑 **PBKDF2-SHA256** — password-based key derivation (600,000 iterations)
- 🛡️ **HMAC-SHA256** — per-chunk integrity + chunk-index in AAD (prevents reordering)
- 📦 **64 KB Chunking** — large files split, each chunk independently encrypted
- ✅ **SHA-256 file integrity** — verified on upload and download
- 🌐 **ECDH X25519** — ephemeral session key exchange for forward secrecy
- 🖥️ **GUI + CLI** — dark professional GUI + server/client Python modules
- 📋 **Activity Log** — timestamped operation log with status indicators
- 🗃️ **Zero-knowledge server** — server stores only ciphertext, never decrypts
- 📊 **Security Info tab** — full threat model + mitigation documentation

---

## 🚀 How to Run

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/SecureVault.git
cd SecureVault

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch GUI (starts both server + client)
python gui.py

# OR run server and client separately:
python server.py          # Terminal 1
python client_demo.py     # Terminal 2
```

---

## 🗂️ Project Structure

```
SecureVault/
│
├── gui.py              # GUI — file manager + server control + log
├── server.py           # TCP file server — stores encrypted files
├── client.py           # Client — encrypts, uploads, downloads, decrypts
├── crypto_engine.py    # AES-256-GCM + HMAC + PBKDF2 + ECDH
├── client_demo.py      # CLI demo script
├── requirements.txt
│
├── server_storage/     # Server stores encrypted .svlt files here
└── README.md
```

---

## 🔬 How It Works

```
CLIENT SIDE                          SERVER SIDE
───────────                          ───────────
User selects file
       ↓
Derive AES-256 key
(PBKDF2 + password + salt)
       ↓
Split file into 64 KB chunks
       ↓
For each chunk:
  Generate random 96-bit IV
  AES-256-GCM encrypt
  (chunk_index in AAD)
  HMAC-SHA256 over chunk
       ↓
Compute SHA-256 of
encrypted file
       ↓
TCP upload ──────────────────────→  Receive encrypted bytes
                                    Verify SHA-256
                                    Store as .svlt (ciphertext only)
                                    Never decrypts!
                                    ↓
                                    Return stored_name

CLIENT DOWNLOAD
       ↓
Request file by stored_name
       ↓
Receive encrypted file ←────────── Stream from disk
Verify SHA-256
       ↓
For each chunk:
  Verify HMAC (fast fail)
  Verify chunk index (AAD)
  AES-256-GCM decrypt
  Verify GCM auth tag
       ↓
Write plaintext to disk ✓
```

---

## 🔒 Encrypted File Format

```
[4B magic "SVLT"][1B version][32B salt][32B file HMAC]
[Chunk 0][Chunk 1]...[Chunk N]

Each chunk:
[4B chunk_index][12B IV][ciphertext + 16B GCM tag][32B HMAC]
```

---

## 🛡️ Threat Model

| Threat | Mitigation |
|---|---|
| **Man-in-the-Middle** | ECDH X25519 key exchange + end-to-end HMAC verification |
| **Data Tampering** | AES-GCM auth tag (128-bit) + HMAC-SHA256 per chunk |
| **Replay Attack** | Random 96-bit IV per chunk — identical plaintext → different ciphertext |
| **Chunk Reordering** | Chunk index in GCM Additional Authenticated Data (AAD) |
| **Brute Force** | PBKDF2 with 600,000 iterations + 256-bit random salt |
| **Key Exposure** | Session keys never written to disk; ECDH forward secrecy |
| **Server Compromise** | Zero-knowledge server — stores only ciphertext, never decrypts |
| **Weak Password** | PBKDF2 stretches any password to 256-bit key |

---

## 📚 Concepts Covered

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation
- ECDH X25519 ephemeral key exchange
- HMAC-SHA256 per-chunk integrity
- Chunked file transfer with resume capability
- Zero-knowledge server architecture
- Threat modeling: MITM, replay, tampering, brute force
- TCP socket programming in Python

---

## ⚠️ Production Considerations

This is an educational prototype. Production deployment requires:
- TLS 1.3 for transport layer security
- Hardware Security Module (HSM) for key storage
- Biometric / 2FA authentication
- Audit logging and intrusion detection
- Formal security review / penetration test

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

```
⭐ Star this repo if you found it useful!
```
