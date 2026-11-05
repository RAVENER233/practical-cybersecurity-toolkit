
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
KEY_FILE = BASE_DIR / "lab.key"


def decrypt_files():
    if not KEY_FILE.is_file():
        raise FileNotFoundError("Encryption key not found.")

    key = KEY_FILE.read_bytes()
    aes = AESGCM(key)

    decrypted_count = 0

    for encrypted_path in SANDBOX.glob("*.enc"):

        data = encrypted_path.read_bytes()

        if len(data) < 28:
            print(f"[!] Invalid encrypted file: {encrypted_path.name}")
            continue

        nonce = data[:12]
        ciphertext = data[12:]

        try:
            original = aes.decrypt(
                nonce,
                ciphertext,
                None
            )

        except Exception:
            print(f"[!] Decryption failed: {encrypted_path.name}")
            continue

        output_path = encrypted_path.with_suffix(".decrypted")

        if output_path.exists():
            print(f"[!] Output already exists: {output_path.name}")
            continue

        with open(output_path, "xb") as output:
            output.write(original)

        decrypted_count += 1

        print(f"[+] Restored copy: {output_path.name}")

    print(f"\n[+] Total decrypted copies: {decrypted_count}")


if __name__ == "__main__":
    try:
        decrypt_files()
    except Exception as error:
        print(f"[!] Error: {error}")
