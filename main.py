"""
Text Encryption & Decryption Tool + Hash Comparison
==================================================
Educational cybersecurity project demonstrating:

Classical ciphers:
- Caesar Cipher
- Vigenère Cipher

Modern symmetric encryption:
- AES-256-CBC (manual)
- Fernet (AES-128 + HMAC authentication)

Hash functions comparison:
- MD5, SHA-1, SHA-256, SHA-512

Author: [Your Name]
GitHub: [your-github-username]
"""

import os
import hashlib
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64


# ────────────────────────────────────────────────
#               CLASSICAL CIPHERS
# ────────────────────────────────────────────────

def caesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def vigenere_encrypt(text: str, key: str) -> str:
    key = key.upper()
    result = ""
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + shift - 97) % 26 + 97)
            key_index += 1
        else:
            result += char
    return result


def vigenere_decrypt(text: str, key: str) -> str:
    key = key.upper()
    result = ""
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                result += chr((ord(char) - shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) - shift - 97) % 26 + 97)
            key_index += 1
        else:
            result += char
    return result


# ────────────────────────────────────────────────
#              AES-256-CBC (manual)
# ────────────────────────────────────────────────

def aes_encrypt(plaintext: str, key: str) -> str:
    key_bytes = key.encode('utf-8').ljust(32)[:32]
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def aes_decrypt(ciphertext_b64: str, key: str) -> str:
    key_bytes = key.encode('utf-8').ljust(32)[:32]
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


# ────────────────────────────────────────────────
#                    FERNET
# ────────────────────────────────────────────────

def fernet_generate_key() -> str:
    """Generate a new Fernet key (save this securely!)"""
    return Fernet.generate_key().decode('utf-8')


def fernet_encrypt(text: str, key: str) -> str:
    try:
        f = Fernet(key.encode('utf-8'))
        return f.encrypt(text.encode('utf-8')).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Fernet encryption failed: {e}")


def fernet_decrypt(ciphertext: str, key: str) -> str:
    try:
        f = Fernet(key.encode('utf-8'))
        return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        raise ValueError("Invalid Fernet token - wrong key or corrupted data")
    except Exception as e:
        raise ValueError(f"Fernet decryption failed: {e}")


# ────────────────────────────────────────────────
#               HASH FUNCTIONS
# ────────────────────────────────────────────────

HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def compute_hash(text: str, algorithm: str) -> str:
    if algorithm not in HASH_FUNCTIONS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_func = HASH_FUNCTIONS[algorithm]()
    hash_func.update(text.encode('utf-8'))
    return hash_func.hexdigest()


def hash_comparison_menu():
    print("\n" + "="*60)
    print("          HASH FUNCTION COMPARISON")
    print("="*60)
    
    text = input("Enter text to hash: ").strip()
    if not text:
        print("No text entered.")
        return
    
    print("\nResults:")
    print("-"*70)
    print(f"{'Algorithm':<10} {'Hash value':<65} {'Length'}")
    print("-"*70)
    
    for algo in ["md5", "sha1", "sha256", "sha512"]:
        h = compute_hash(text, algo)
        print(f"{algo.upper():<10} {h:<65} {len(h)}")
    print("-"*70)
    
    print("\nNote:")
    print("• MD5 & SHA-1 are considered cryptographically broken")
    print("• Use SHA-256 or SHA-512 (or better: SHA3, BLAKE2) for security")


# ────────────────────────────────────────────────
#               FILE ENCRYPTION
# ────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, method: str, key=None, shift=None):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if method == "caesar":
            result = caesar_encrypt(content, shift)
        elif method == "vigenere":
            result = vigenere_encrypt(content, key)
        elif method == "aes":
            result = aes_encrypt(content, key)
        elif method == "fernet":
            result = fernet_encrypt(content, key)
        else:
            raise ValueError("Unknown method")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        
        print(f"Encrypted file saved → {output_path}")
        
    except Exception as e:
        print(f"Encryption failed: {e}")


def decrypt_file(input_path: str, output_path: str, method: str, key=None, shift=None):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if method == "caesar":
            result = caesar_decrypt(content, shift)
        elif method == "vigenere":
            result = vigenere_decrypt(content, key)
        elif method == "aes":
            result = aes_decrypt(content, key)
        elif method == "fernet":
            result = fernet_decrypt(content, key)
        else:
            raise ValueError("Unknown method")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        
        print(f"Decrypted file saved → {output_path}")
        
    except InvalidToken:
        print("Decryption failed: Wrong Fernet key or corrupted data")
    except Exception as e:
        print(f"Decryption failed: {e}")


# ────────────────────────────────────────────────
#                   MAIN MENU
# ────────────────────────────────────────────────

def main():
    print("="*70)
    print("      TEXT ENCRYPTION / DECRYPTION + HASH COMPARISON TOOL")
    print("="*70)
    
    while True:
        print("\nMain Menu:")
        print("  1. Encrypt text")
        print("  2. Decrypt text")
        print("  3. Encrypt file")
        print("  4. Decrypt file")
        print("  5. Hash comparison (MD5, SHA-1, SHA-256, SHA-512)")
        print("  6. Generate new Fernet key")
        print("  7. Exit")
        
        choice = input("\nEnter choice (1-7): ").strip()
        
        if choice == "7":
            print("\nThank you for using the tool!\n")
            break
            
        if choice not in ["1","2","3","4","5","6"]:
            print("Invalid choice.")
            continue
            
        if choice == "5":
            hash_comparison_menu()
            continue
            
        if choice == "6":
            key = fernet_generate_key()
            print("\nNew Fernet key (SAVE THIS SECURELY!):")
            print(key)
            print("\nYou can use this key for Fernet encryption/decryption.")
            continue
            
        # All other options need encryption method
        print("\nAvailable methods:")
        print("  caesar    vigenere    aes    fernet")
        method = input("Choose method: ").lower().strip()
        
        if method not in ["caesar", "vigenere", "aes", "fernet"]:
            print("Invalid method!")
            continue
            
        key = None
        shift = None
        
        if method == "caesar":
            try:
                shift = int(input("Enter shift (1-25): "))
                if not 1 <= shift <= 25:
                    print("Shift must be 1–25")
                    continue
            except ValueError:
                print("Invalid number")
                continue
                
        elif method in ["vigenere", "aes", "fernet"]:
            key = getpass("Enter key/password: ")
            if not key:
                print("Key cannot be empty")
                continue
                
            if method == "fernet" and len(key) != 44:
                print("Warning: Fernet keys are usually 44 characters (base64).")
                print("You can continue, but it may fail if format is wrong.")
        
        if choice in ["1", "3"]:  # Encrypt
            if choice == "1":
                text = input("Enter text to encrypt: ")
                if not text:
                    continue
                    
                try:
                    if method == "caesar":
                        result = caesar_encrypt(text, shift)
                    elif method == "vigenere":
                        result = vigenere_encrypt(text, key)
                    elif method == "aes":
                        result = aes_encrypt(text, key)
                    elif method == "fernet":
                        result = fernet_encrypt(text, key)
                        
                    print("\nEncrypted result:")
                    print("-"*70)
                    print(result)
                    print("-"*70)
                except Exception as e:
                    print(f"Encryption error: {e}")
                    
            else:  # file
                inp = input("Input file path: ").strip()
                out = input("Output file (or Enter for auto): ").strip()
                if not out:
                    out = inp + ".enc"
                encrypt_file(inp, out, method, key=key, shift=shift)
                
        else:  # Decrypt
            if choice == "2":
                text = input("Enter encrypted text: ")
                if not text:
                    continue
                    
                try:
                    if method == "caesar":
                        result = caesar_decrypt(text, shift)
                    elif method == "vigenere":
                        result = vigenere_decrypt(text, key)
                    elif method == "aes":
                        result = aes_decrypt(text, key)
                    elif method == "fernet":
                        result = fernet_decrypt(text, key)
                        
                    print("\nDecrypted result:")
                    print("-"*70)
                    print(result)
                    print("-"*70)
                except Exception as e:
                    print(f"Decryption error: {e}")
                    
            else:  # file
                inp = input("Input encrypted file path: ").strip()
                out = input("Output file (or Enter for auto): ").strip()
                if not out:
                    out = inp + ".dec" if ".enc" not in inp else inp.replace(".enc", ".dec")
                decrypt_file(inp, out, method, key=key, shift=shift)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExited by user.")