#  Advanced Encryption Tool (AES-256 GCM)

A simple and secure desktop application for encrypting and decrypting files using military-grade AES-256 GCM encryption with PBKDF2 key derivation.

## Features

- **AES-256 GCM Encryption**: Military-grade symmetric encryption with authenticated encryption
- **PBKDF2-HMAC-SHA256**: Secure password-based key derivation with 100,000 iterations
- **Per-File Salt & Nonce**: Each file uses unique salt and nonce for security
- **User-Friendly GUI**: Simple Tkinter interface for file selection and encryption/decryption
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Requirements

- Python 3.9 or higher
- cryptography >= 41.0.0

## Installation

### 1. Clone or Download the Repository

```bash
git clone https://github.com/Jaynavghane/crypto-tool.git
cd crypto-tool
```

### 2. Create a Virtual Environment (Recommended)

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install directly:
```bash
pip install cryptography>=41.0.0
```

## Usage

### Running the Application

```bash
python main.py
```

This will launch the GUI window.

--------------------------

### OutPut

<img width="800" height="425" alt="Image" src="https://github.com/user-attachments/assets/03710016-bea6-4e80-976f-afd1ea2b6dc5" />

<img width="800" height="425" alt="Image" src="https://github.com/user-attachments/assets/df3d15a1-60ff-44a7-9fd2-9c9065f6abe7" />

--------------------------------------------------------------------------------------------------------------------------

### Steps to Encrypt a File

1. Click **"Browse"** to select the file you want to encrypt
2. The output path will automatically be set to `filename.enc`
3. Click **"Save As"** to choose a different output location if needed
4. Enter a strong password
5. Click **"Encrypt"** button
6. A success message will confirm the file has been encrypted

### Steps to Decrypt a File

1. Click **"Browse"** to select an encrypted `.enc` file
2. Update the output path if desired (default removes `.enc` extension)
3. Enter the password used during encryption
4. Click **"Decrypt"** button
5. A success message will confirm the file has been decrypted

## File Format

Encrypted files have the following structure:

| Component | Size | Description |
|-----------|------|-------------|
| Magic Number | 4 bytes | `CTAE` identifier |
| Version | 1 byte | Format version |
| Salt | 16 bytes | Random salt for PBKDF2 |
| Nonce | 12 bytes | Random nonce for GCM |
| Ciphertext | Variable | Encrypted data + 16-byte authentication tag |

## Security Notes

- **Password Strength**: Use a strong password (12+ characters with mix of uppercase, lowercase, numbers, symbols)
- **Password Recovery**: Losing your password means losing access to encrypted files permanently
- **Salt & Nonce**: These are non-secret values stored with the ciphertext for decryption
- **Authentication**: GCM mode provides both confidentiality and integrity verification
- **Iterations**: PBKDF2 uses 100,000 iterations to resist brute-force attacks

## Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"
Install the cryptography module:
```bash
pip install cryptography
```

### "Decryption failed. Wrong password or file corrupted."
- Verify you're using the correct password
- Ensure the encrypted file hasn't been corrupted
- Confirm you're trying to decrypt an actually encrypted file

### Application window doesn't open
Ensure Tkinter is installed. On some Linux distributions:
```bash
sudo apt-get install python3-tk
```

## License

This project is provided as-is for educational and personal use.

## Support

For issues or questions, please refer to the project documentation or contact the maintainers.

--------------------------------------------------------------
* Company: CODTECH IT SOLUTIONS
* Name: Jay Navghane
* Intern ID: COD08111
* Domain: Cyber security & Ethical Hacking
* Duration: 6 weeks
* Mentor: Neela Santosh


