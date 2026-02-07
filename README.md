# 🔐 Encryption-Decryption Project

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/0407ganesh/Encryption-Decryption-project?style=flat-square)](https://github.com/0407ganesh/Encryption-Decryption-project/stargazers)

A comprehensive Python project demonstrating secure text encryption and decryption using modern cryptographic techniques. Perfect for learning cybersecurity fundamentals and implementing production-ready encryption solutions.

---

## ✨ Features

### 🔑 **Fernet Encryption/Decryption**
- ⚡ Easy-to-use, authenticated AES-128 encryption
- 🛡️ Includes HMAC for message authentication
- 🔄 Built-in key generation option
- ✅ Industry-standard symmetric encryption

### 🔗 **Hash Function Comparison**
- 📊 MD5, SHA-1, SHA-256, SHA-512
- 📏 Shows output length for each algorithm
- ⚠️ Warns about broken/deprecated algorithms
- 📈 Educational comparison of hash functions

---

## 🔒 Security Notes

> **⚠️ Important:** Always use the most secure methods for production environments.

| Algorithm | Security Status | Use Case |
|-----------|-----------------|----------|
| **Fernet** | ✅ **Recommended** | Production encryption |
| **AES-CBC** (Manual) | ⚠️ Educational | Learning purposes only |
| **MD5** | ❌ **Broken** | Do not use for security |
| **SHA-1** | ❌ **Broken** | Do not use for security |

### 🏆 Best Practices for Real Applications:
- 🔐 **Key Derivation:** Argon2, PBKDF2, or scrypt
- 🎯 **Authenticated Encryption:** AES-GCM or ChaCha20-Poly1305
- 🔑 **Key Generation:** Use `secrets` or `os.urandom()` for cryptographic randomness

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/0407ganesh/Encryption-Decryption-project.git
cd Encryption-Decryption-project

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Run the main program
python main.py
```

---

## 📁 Project Structure

```
Encryption-Decryption-project/
├── main.py              # Main application
├── requirements.txt     # Project dependencies
└── README.md           # This file
```

---

## 📚 What You'll Learn

- 🔐 **Cryptographic Principles:** Symmetric vs asymmetric encryption
- 🔑 **Key Management:** Secure key generation and storage
- 🛡️ **Authentication:** HMAC and message authentication codes
- 📊 **Hash Functions:** Different algorithms and their security levels
- 💻 **Python Cryptography:** Using the `cryptography` library
- ✅ **Best Practices:** Industry standards for secure coding

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Authors

- **Ganesh** - [@0407ganesh](https://github.com/0407ganesh)
- **Neeraja** - [@rneeraja080803](https://github.com/rneeraja080803)

---

## 💡 Disclaimer

⚠️ This project is for **educational purposes**. Always consult security experts before implementing encryption in production systems. Improper use of cryptography can lead to security vulnerabilities.

---

## 🔗 Resources

- [Python cryptography library](https://cryptography.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

---

**Happy Coding! 🚀 Stay Secure! 🔒**
