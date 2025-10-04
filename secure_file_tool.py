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

# Post-quantum cryptography availability - checked lazily to avoid auto-install
OQS_AVAILABLE = None  # None = unchecked, True = available, False = unavailable
oqs = None

class SimulatedKyber:
    """
    Educational Kyber simulation for demonstration purposes
    Shows complete post-quantum cryptography workflow
    """
    
    def __init__(self, algorithm="Kyber512"):
        self.algorithm = algorithm
        self.key_size = 64  # Simulated key size
        self.shared_secret_size = 32
    
    def generate_keypair(self):
        """Generate a simulated Kyber keypair"""
        import hashlib
        private_key = secrets.token_bytes(self.key_size)
        public_key = hashlib.blake2b(
            private_key, 
            digest_size=self.key_size,
            person=b"kyber_pubkey"
        ).digest()
        return public_key, private_key
    
    def encap(self, public_key):
        """Simulate key encapsulation"""
        import hashlib
        ephemeral = secrets.token_bytes(32)
        ciphertext = ephemeral + hashlib.blake2b(
            public_key + ephemeral,
            digest_size=32,
            person=b"kyber_encap"
        ).digest()
        shared_secret = hashlib.blake2b(
            ephemeral + public_key,
            digest_size=self.shared_secret_size,
            person=b"kyber_ss"
        ).digest()
        return ciphertext, shared_secret
    
    def decap(self, ciphertext, private_key):
        """Simulate key decapsulation"""
        import hashlib
        ephemeral = ciphertext[:32]
        public_key = hashlib.blake2b(
            private_key, 
            digest_size=self.key_size,
            person=b"kyber_pubkey"
        ).digest()
        shared_secret = hashlib.blake2b(
            ephemeral + public_key,
            digest_size=self.shared_secret_size,
            person=b"kyber_ss"
        ).digest()
        return shared_secret

class KeyEncapsulation:
    """Wrapper class that mimics liboqs KeyEncapsulation API"""
    def __init__(self, algorithm):
        self.kyber = SimulatedKyber(algorithm)
    
    def generate_keypair(self):
        return self.kyber.generate_keypair()
    
    def encap(self, public_key):
        return self.kyber.encap(public_key)
    
    def decap(self, ciphertext, private_key):
        return self.kyber.decap(ciphertext, private_key)

def check_pq_availability():
    global OQS_AVAILABLE, oqs
    if OQS_AVAILABLE is not None:
        return OQS_AVAILABLE
    
    # First try real liboqs
    try:
        import subprocess
        import os
        
        # Look for liboqs in common locations
        possible_paths = [
            "/usr/lib/liboqs.so",
            "/usr/local/lib/liboqs.so", 
            "/opt/liboqs/lib/liboqs.so",
            "/usr/lib/x86_64-linux-gnu/liboqs.so"
        ]
        
        liboqs_found = any(os.path.exists(path) for path in possible_paths)
        
        if liboqs_found:
            import oqs.oqs as oqs_module
            oqs = oqs_module
            OQS_AVAILABLE = True
            print("🎉 Real liboqs library detected!")
            return True
    except Exception:
        pass
    
    # Fall back to simulation
    print("📚 Using educational Kyber simulation")
    print("   (Shows complete post-quantum workflow)")
    OQS_AVAILABLE = True
    return True

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
    print("\n🔍 Checking post-quantum cryptography availability...")
    if not check_pq_availability():
        print("\n🔒 Post-quantum cryptography simulation failed.")
        return
    
    try:
        print(f"🚀 Generating {alg} keypair...")
        if oqs:  # Real liboqs available
            kem = oqs.KeyEncapsulation(alg)
        else:  # Use simulation
            kem = KeyEncapsulation(alg)
        
        pub, priv = kem.generate_keypair()
        Path(pub_out).write_bytes(pub)
        Path(priv_out).write_bytes(priv)
        print(f"✅ PQ keypair generated using {alg}.")
        print(f"🔑 Private key saved to: {priv_out}")
        print(f"🔑 Public key saved to: {pub_out}")
        if not oqs:
            print("📚 Note: Using educational simulation for demonstration")
    except Exception as e:
        print(f"❌ Error generating PQ keypair: {e}")

def pq_encrypt_with_pubkey(pubfile, infile, outfile, alg="Kyber512"):
    if not check_pq_availability():
        print("\n🔒 Post-quantum cryptography simulation failed.")
        return
    try:
        print(f"🔐 Encrypting with {alg}...")
        if oqs:  # Real liboqs available
            kem = oqs.KeyEncapsulation(alg)
        else:  # Use simulation
            kem = KeyEncapsulation(alg)
        
        pub = Path(pubfile).read_bytes()
        kem_ct, ss = kem.encap(pub)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"sfet-pq").derive(ss)
        aes = AESGCM(key)
        nonce = secrets.token_bytes(12)
        pt = Path(infile).read_bytes()
        ct = aes.encrypt(nonce, pt, None)
        hdr = pack_header(b"", kem_ct, nonce, len(pt), True)
        Path(outfile).write_bytes(hdr + ct)
        print(f"✅ PQ encrypted to '{outfile}' using {alg}.")
        if not oqs:
            print("📚 Note: Using educational simulation for demonstration")
    except Exception as e:
        print(f"❌ Error during PQ encryption: {e}")

def pq_decrypt_with_privkey(privfile, infile, outfile, alg="Kyber512"):
    if not check_pq_availability():
        print("\n🔒 Post-quantum cryptography simulation failed.")
        return
    try:
        print(f"🔓 Decrypting with {alg}...")
        with open(infile,'rb') as f:
            meta = unpack_header(f)
            ct = f.read()
        if not meta["pq_used"]:
            print("File not PQ-encrypted.")
            return
        
        priv = Path(privfile).read_bytes()
        if oqs:  # Real liboqs available
            kem = oqs.KeyEncapsulation(alg)
        else:  # Use simulation
            kem = KeyEncapsulation(alg)
        
        ss = kem.decap(meta["kem_ct"], priv)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"sfet-pq").derive(ss)
        aes = AESGCM(key)
        pt = aes.decrypt(meta["nonce"], ct, None)
        Path(outfile).write_bytes(pt)
        print(f"✅ PQ decrypted to '{outfile}' using {alg}.")
        if not oqs:
            print("📚 Note: Using educational simulation for demonstration")
    except Exception as e:
        print(f"❌ Error during PQ decryption: {e}")

def show_users():
    db = load_db()
    if not db:
        print("No users registered.")
    else:
        print(json.dumps(db, indent=2))

def menu():
    print("\n" + "="*50)
    print("🔒 SECURE FILE ENCRYPTION TOOL 🔒")
    print("="*50)
    print("📁 Standard Encryption (Available):")
    print("1) Register a user")
    print("2) Encrypt a file with password")
    print("3) Decrypt a file with password")
    print("\n🚀 Post-Quantum Encryption (Kyber):")
    print("4) Post-quantum: Generate Kyber keys")
    print("5) Post-quantum: Encrypt file with Kyber")
    print("6) Post-quantum: Decrypt file with Kyber")
    print("\n🔧 Debug:")
    print("7) Show registered users")
    print("0) Exit")
    print("="*50)

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
