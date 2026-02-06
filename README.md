## New Features Added

- **Fernet** encryption/decryption  
  → Easy-to-use, authenticated AES-128 + HMAC  
  → Includes key generation option

- **Hash function comparison**  
  → MD5, SHA-1, SHA-256, SHA-512  
  → Shows output length and warns about broken algorithms

## Security Notes

- **Fernet** is the most secure & recommended method in this project
- **AES-CBC** (manual) is shown for learning purposes only
- **MD5 & SHA-1** are broken — never use them for security purposes
- Real applications should use:
  - Argon2 / PBKDF2 / scrypt for key derivation
  - AES-GCM or ChaCha20-Poly1305 for authenticated encryption
  - Secure random key generation