#!/usr/bin/env python3
"""
Demo script to show working encryption features
"""
import sys
sys.path.append('.')
from secure_file_tool import register_user, encrypt_with_password, decrypt_with_password, verify_user, load_db

def demo_encryption():
    print("🔒 DEMONSTRATING WORKING ENCRYPTION FEATURES")
    print("=" * 50)
    
    # Check if user exists
    if verify_user("demo", "password123"):
        print("✅ Demo user already exists")
    else:
        print("📝 Registering demo user...")
        register_user("demo", "password123")
    
    # Encrypt the test file
    print("\n🔐 Encrypting test file...")
    encrypt_with_password("demo", "password123", "test_file.txt", "encrypted_file.sfet")
    
    # Decrypt the file
    print("\n🔓 Decrypting file...")
    decrypt_with_password("demo", "password123", "encrypted_file.sfet", "decrypted_file.txt")
    
    # Show results
    print("\n📁 Files created:")
    import os
    for f in ["test_file.txt", "encrypted_file.sfet", "decrypted_file.txt"]:
        if os.path.exists(f):
            size = os.path.getsize(f)
            print(f"   {f} ({size} bytes)")
    
    # Verify content
    print("\n🔍 Verifying decryption...")
    try:
        with open("test_file.txt", "r") as f1, open("decrypted_file.txt", "r") as f2:
            original = f1.read()
            decrypted = f2.read()
            if original == decrypted:
                print("✅ SUCCESS: Decrypted content matches original!")
            else:
                print("❌ FAILED: Content mismatch")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    demo_encryption()