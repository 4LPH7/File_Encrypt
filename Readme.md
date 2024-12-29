# Secure File Encryption System

## Overview
The **Secure File Encryption System** is a user-friendly application that provides robust file security through encryption, access control, and integrity verification. The system integrates AES-256 encryption, RSA key management, access control lists (ACLs), and secure file deletion functionalities in a graphical interface powered by `customtkinter`.

---

## Features

1. **File Encryption (AES-256):** Encrypts files with a password.
2. **File Decryption:** Decrypts files using the original password.
3. **RSA Key Pair Generation:** Generates and manages public/private key pairs.
4. **Access Control List (ACL):** Create and manage ACLs for files.
5. **Integrity Verification:** Checks file integrity using SHA-256.
6. **Secure File Deletion:** Permanently deletes files by overwriting them.
7. **User-Friendly GUI:** Intuitive graphical interface with hover tooltips for better usability.

---

## Installation

### Prerequisites
Ensure you have Python 3.9 or above installed.

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/secure-file-encryption.git
   cd secure-file-encryption
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python gui.py
   ```

---

## Usage

1. **Encrypt a File:**
   - Click on `Encrypt File`, select the file, and enter a password.
2. **Decrypt a File:**
   - Click on `Decrypt File`, select the file, and enter the password used during encryption.
3. **Generate RSA Keys:**
   - Click on `Generate RSA Keys`, provide a filename, and save the generated keys.
4. **Create an ACL:**
   - Click on `Create ACL`, select a file, and specify user names.
5. **Verify Integrity:**
   - Click on `Verify Integrity`, select a file, and provide the expected hash.
6. **Secure Delete:**
   - Click on `Secure Delete` and select a file to permanently delete it.

---

## Dependencies

- `customtkinter` (for GUI)
- `cryptography` (for AES and RSA)
- `tkinter` (for file dialog and messages)
- `os` and `hashlib` (for secure deletion and integrity checks)

---

## Requirements.txt
```
customtkinter==5.0.0
cryptography==41.0.3
