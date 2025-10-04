#!/usr/bin/env python3
"""
Menu-driven Secure File Encryption Tool (educational)
- Password-based AES-GCM using Argon2 for KDF
- Optional hooks for post-quantum (Kyber) if liboqs is installed
"""
from pathlib import Path
import struct, secrets, json, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type

try:
    import oqs
    OQS_AVAILABLE = True
except Exception:
    OQS_AVAILABLE = False

USER_DB = Path("user_db.json")
MAGIC = b"SFET"
VERSION = 1

def save_db(db):
    USER_DB.write_text(json.dumps(db, indent=2))

def load_db():
    if USER_DB.exists():
        return json.loads(USER_DB.read_text())
    return {}

def derive_key_from_password(password: str, salt: bytes, key_len: int = 32) -> bytes:
    return hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=key_len,
        type=Type.ID,
    )

def register_user(username: str, password: str):
    db = load_db()
    if username in db:
        print("User already exists.")
        return
    salt = secrets.token_bytes(16)
    verifier = derive_key_from_password(password, salt, key_len=32)
    db[username] = {"salt": salt.hex(), "verifier": verifier.hex()}
    save_db(db)
    print(f"Registered user '{username}'.")

def verify_user(username: str, password: str) -> bool:
    db = load_db()
    if username not in db:
        return False
    salt = bytes.fromhex(db[username]["salt"])
    expect = bytes.fromhex(db[username]["verifier"])
    got = derive_key_from_password(password, salt, key_len=len(expect))
    return got == expect

def pack_header(salt: bytes, kem_ct: bytes, nonce: bytes, plen: int, pq_used: bool):
    flags = 1 if pq_used else 0
    parts = [
        MAGIC,
        struct.pack("B", VERSION),
        struct.pack("B", flags),
        struct.pack(">H", len(salt)),
        salt,
        struct.pack(">H", len(kem_ct)),
        kem_ct,
        nonce,
        struct.pack(">Q", plen),
    ]
    return b"".join(parts)

def unpack_header(f):
    magic = f.read(4)
    if magic != MAGIC:
        raise ValueError("Bad file format")
    version = struct.unpack("B", f.read(1))[0]
    flags = struct.unpack("B", f.read(1))[0]
    pq_used = bool(flags & 1)
    salt_len = struct.unpack(">H", f.read(2))[0]
    salt = f.read(salt_len)
    kem_len = struct.unpack(">H", f.read(2))[0]
    kem_ct = f.read(kem_len) if kem_len else b""
    nonce = f.read(12)
    plen = struct.unpack(">Q", f.read(8))[0]
    return {
        "version": version,
        "pq_used": pq_used,
        "salt": salt,
        "kem_ct": kem_ct,
        "nonce": nonce,
        "plen": plen,
    }

def encrypt_with_password(username, password, infile, outfile):
    if not verify_user(username, password):
        print("Authentication failed.")
        return
    db = load_db()
    salt = bytes.fromhex(db[username]["salt"])
    key = derive_key_from_password(password, salt, key_len=32)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    pt = Path(infile).read_bytes()
    ct = aes.encrypt(nonce, pt, None)
    hdr = pack_header(salt, b"", nonce, len(pt), False)
    Path(outfile).write_bytes(hdr + ct)
    print(f"Encrypted '{outfile}'.")

def decrypt_with_password(username, password, infile, outfile):
    if not verify_user(username, password):
        print("Authentication failed.")
        return
    with open(infile, 'rb') as f:
        meta = unpack_header(f)
        ct = f.read()
    if meta["pq_used"]:
        print("File uses post-quantum mode; use pq decrypt if supported.")
        return
    salt = meta["salt"]   # fixed
    key = derive_key_from_password(password, salt, key_len=32)
    aes = AESGCM(key)
    pt = aes.decrypt(meta["nonce"], ct, None)
    Path(outfile).write_bytes(pt)
    print(f"Decrypted to '{outfile}'.")

def pq_generate_keypair(priv_out, pub_out, alg="Kyber512"):
    if not OQS_AVAILABLE:
        print("liboqs not available. Install liboqs-python and liboqs.")
        return
    kem = oqs.KeyEncapsulation(alg)
    pub, priv = kem.generate_keypair()
    Path(pub_out).write_bytes(pub)
    Path(priv_out).write_bytes(priv)
    print("PQ keypair generated.")

def pq_encrypt_with_pubkey(pubfile, infile, outfile, alg="Kyber512"):
    if not OQS_AVAILABLE:
        print("liboqs not available. Install liboqs-python and liboqs.")
        return
    kem = oqs.KeyEncapsulation(alg)
    pub = Path(pubfile).read_bytes()
    kem_ct, ss = kem.encap(pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"sfet-pq").derive(ss)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    pt = Path(infile).read_bytes()
    ct = aes.encrypt(nonce, pt, None)
    hdr = pack_header(b"", kem_ct, nonce, len(pt), True)
    Path(outfile).write_bytes(hdr + ct)
    print(f"PQ encrypted to '{outfile}'.")

def pq_decrypt_with_privkey(privfile, infile, outfile, alg="Kyber512"):
    if not OQS_AVAILABLE:
        print("liboqs not available. Install liboqs-python and liboqs.")
        return
    with open(infile,'rb') as f:
        meta = unpack_header(f)
        ct = f.read()
    if not meta["pq_used"]:
        print("File not PQ-encrypted.")
        return
    priv = Path(privfile).read_bytes()
    kem = oqs.KeyEncapsulation(alg)
    ss = kem.decap(meta["kem_ct"], priv)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"sfet-pq").derive(ss)
    aes = AESGCM(key)
    pt = aes.decrypt(meta["nonce"], ct, None)
    Path(outfile).write_bytes(pt)
    print(f"PQ decrypted to '{outfile}'.")

def show_users():
    db = load_db()
    if not db:
        print("No users registered.")
    else:
        print(json.dumps(db, indent=2))

def menu():
    print("===== Secure File Encryption Tool =====")
    print("1) Register a user")
    print("2) Encrypt a file with password")
    print("3) Decrypt a file with password")
    print("4) Post-quantum: Generate Kyber keys (optional)")
    print("5) Post-quantum: Encrypt file with Kyber (optional)")
    print("6) Post-quantum: Decrypt file with Kyber (optional)")
    print("7) Show registered users (debug)")
    print("0) Exit")

def main():
    while True:
        menu()
        choice = input("Choose an option: ").strip()
        if choice == "1":
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            register_user(u,p)
        elif choice == "2":
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            inf = input("Input file path: ").strip()
            outf = input("Output file path: ").strip()
            encrypt_with_password(u,p,inf,outf)
        elif choice == "3":
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            inf = input("Input encrypted file: ").strip()
            outf = input("Output file path: ").strip()
            decrypt_with_password(u,p,inf,outf)
        elif choice == "4":
            priv = input("Private key file path (save): ").strip()
            pub = input("Public key file path (save): ").strip()
            pq_generate_keypair(priv,pub)
        elif choice == "5":
            pub = input("Public key file path: ").strip()
            inf = input("Input file path: ").strip()
            outf = input("Output file path: ").strip()
            pq_encrypt_with_pubkey(pub,inf,outf)
        elif choice == "6":
            priv = input("Private key file path: ").strip()
            inf = input("Input file path: ").strip()
            outf = input("Output file path: ").strip()
            pq_decrypt_with_privkey(priv,inf,outf)
        elif choice == "7":
            show_users()
        elif choice == "0":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
