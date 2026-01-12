import os
import json
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "vault.bin"
backend = default_backend()

# ---------------- KEY DERIVATION ----------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=backend
    )
    return kdf.derive(password.encode())

# ---------------- ENCRYPT ----------------
def encrypt_vault(password: str, vault: dict):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    data = json.dumps(vault).encode()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    with open(VAULT_FILE, "wb") as f:
        f.write(salt + iv + ciphertext)

# ---------------- DECRYPT ----------------
def decrypt_vault(password: str) -> dict:
    with open(VAULT_FILE, "rb") as f:
        raw = f.read()

    salt, iv, ciphertext = raw[:16], raw[16:32], raw[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()

    try:
        data = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(data.decode())
    except Exception:
        raise ValueError("Wrong password")

# ---------------- VAULT ACTIONS ----------------
def add_or_update(vault):
    site = input("Site name: ").strip()
    username = input("Username: ").strip()
    password = getpass("Password: ")

    vault[site] = {
        "username": username,
        "password": password
    }
    print("✅ Saved")

def remove_entry(vault):
    site = input("Site to remove: ").strip()
    if site in vault:
        del vault[site]
        print("🗑️ Removed")
    else:
        print("❌ Not found")

def show_entries(vault):
    for site in vault:
        print(f"- {site}")

def view_entry(vault):
    site = input("Site name: ").strip()
    if site in vault:
        confirm = input("Reveal credentials? (y/N): ").lower()
        if confirm == "y":
            print(f"👤 Username: {vault[site]['username']}")
            print(f"🔑 Password: {vault[site]['password']}")
    else:
        print("❌ Not found")

def change_master_password(vault):
    print("\n🔐 Change master password")
    new_pass = getpass("New password: ")
    confirm = getpass("Confirm new password: ")

    if new_pass != confirm:
        print("❌ Passwords do not match")
        return None

    encrypt_vault(new_pass, vault)
    print("✅ Master password changed")
    return new_pass

# ---------------- MAIN APP ----------------
def main():
    if not os.path.exists(VAULT_FILE):
        print("🔐 First-time setup")
        password = getpass("Create master password: ")
        encrypt_vault(password, {})
        print("✅ Vault created")
        return

    password = getpass("Enter master password: ")

    try:
        vault = decrypt_vault(password)
    except ValueError:
        print("❌ Incorrect password")
        return

    while True:
        print("""
1) Add / Update entry
2) Remove entry
3) List sites
4) View username & password
5) Change master password
6) Exit
""")
        choice = input("Select: ").strip()

        if choice == "1":
            add_or_update(vault)
            encrypt_vault(password, vault)

        elif choice == "2":
            remove_entry(vault)
            encrypt_vault(password, vault)

        elif choice == "3":
            show_entries(vault)

        elif choice == "4":
            view_entry(vault)

        elif choice == "5":
            new_password = change_master_password(vault)
            if new_password:
                password = new_password

        elif choice == "6":
            print("🔒 Vault locked")
            break

        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()

