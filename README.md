Secure File Encryption Tool (regenerated)
----------------------------------------
This is an educational, regenerated copy of a menu-driven secure file encryption tool.
It supports:
 - Password-based encryption (Argon2 + AES-GCM)
 - Optional hooks for post-quantum Kyber via liboqs (requires system liboqs + liboqs-python)

Files:
 - secure_file_tool.py  : main menu-driven script
 - requirements.txt     : Python packages to install in a venv
 - README.md            : this file

Quick usage:
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  python secure_file_tool.py

Note: This is for learning only. Do not use as-is for production.