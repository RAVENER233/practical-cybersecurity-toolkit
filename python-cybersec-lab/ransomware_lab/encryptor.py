
import os

from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
KEY_FILE = BASE_DIR / "lab.key"


def create_key():
    key = AESGCM.generate_key(bit_length=256)

    with open(KEY_FILE, "xb") as file:
        file.write(key)

    print("[+] New AES-256 key generated.")


def encrypt_files():
    if not SANDBOX.is_dir():
        raise RuntimeError("Sandbox directory is missing.")

    if not KEY_FILE.is_file():
        create_key()

    key = KEY_FILE.read_bytes()
    aes = AESGCM(key)

    encrypted_count = 0

    for file_path in SANDBOX.iterdir():

        if not file_path.is_file():
            continue

        if file_path.is_symlink():
            continue

        if file_path.suffix in (".enc", ".decrypted"):
            continue

        nonce = os.urandom(12)
        original = file_path.read_bytes()

        ciphertext = aes.encrypt(
            nonce,
            original,
            None
        )

        encrypted_path = Path(str(file_path) + ".enc")

        with open(encrypted_path, "xb") as output:
            output.write(nonce + ciphertext)

        encrypted_count += 1

        print(f"[+] Encrypted copy created: {encrypted_path.name}")

    print(f"\n[+] Total encrypted copies: {encrypted_count}")
    print("[+] Original files have been preserved.")


if __name__ == "__main__":
    try:
        encrypt_files()
    except Exception as error:
        print(f"[!] Error: {error}")
