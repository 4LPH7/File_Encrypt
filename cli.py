import argparse
from encryption import aes_encrypt_file, aes_decrypt_file, generate_rsa_key_pair, rsa_encrypt_aes_key, rsa_decrypt_aes_key
from key_management import derive_key, save_rsa_keys, load_rsa_keys
from access_control import create_acl, grant_access
from integrity import verify_integrity
from secure_deletion import secure_delete

def main():
    parser = argparse.ArgumentParser(description='Secure File Encryption System')
    subparsers = parser.add_subparsers(dest='command')

    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('--password', help='Password for key derivation')

    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--password', help='Password for key derivation')

    # Generate RSA keys
    keygen_parser = subparsers.add_parser('keygen', help='Generate RSA key pair')
    keygen_parser.add_argument('--filename', help='Filename for keys')

    # Encrypt AES key with RSA
    rsa_encrypt_parser = subparsers.add_parser('rsa_encrypt', help='Encrypt AES key with RSA public key')
    rsa_encrypt_parser.add_argument('--aes_key', help='AES key to encrypt')
    rsa_encrypt_parser.add_argument('--public_key', help='RSA public key file')

    # Decrypt AES key with RSA
    rsa_decrypt_parser = subparsers.add_parser('rsa_decrypt', help='Decrypt AES key with RSA private key')
    rsa_decrypt_parser.add_argument('--encrypted_aes_key', help='Encrypted AES key')
    rsa_decrypt_parser.add_argument('--private_key', help='RSA private key file')

    # Create ACL
    acl_parser = subparsers.add_parser('create_acl', help='Create ACL for a file')
    acl_parser.add_argument('file', help='File to create ACL for')
    acl_parser.add_argument('--users', nargs='+', help='List of users')

    # Grant access
    grant_parser = subparsers.add_parser('grant_access', help='Grant access to a user')
    grant_parser.add_argument('file', help='File to grant access to')
    grant_parser.add_argument('--user', help='User to grant access')
    grant_parser.add_argument('--permission', help='Permission to grant')

    # Verify integrity
    verify_parser = subparsers.add_parser('verify', help='Verify file integrity')
    verify_parser.add_argument('file', help='File to verify')
    verify_parser.add_argument('--hash', help='Expected SHA-256 hash')

    # Secure delete
    delete_parser = subparsers.add_parser('delete', help='Securely delete a file')
    delete_parser.add_argument('file', help='File to delete')

    args = parser.parse_args()

    if args.command == 'encrypt':
        password = args.password.encode()
        key, _ = derive_key(password)
        aes_encrypt_file(args.file, key)
    elif args.command == 'decrypt':
        password = args.password.encode()
        key, _ = derive_key(password)
        aes_decrypt_file(args.file, key)
    elif args.command == 'keygen':
        public_key, private_key = generate_rsa_key_pair()
        save_rsa_keys(public_key, private_key, args.filename)
    elif args.command == 'rsa_encrypt':
        with open(args.aes_key, 'rb') as f:
            aes_key = f.read()
        with open(args.public_key, 'rb') as f:
            public_key = f.read()
        encrypted_aes_key = rsa_encrypt_aes_key(aes_key, public_key)
        with open('encrypted_aes_key.bin', 'wb') as f:
            f.write(encrypted_aes_key)
    elif args.command == 'rsa_decrypt':
        with open(args.encrypted_aes_key, 'rb') as f:
            encrypted_aes_key = f.read()
        with open(args.private_key, 'rb') as f:
            private_key = f.read()
        aes_key = rsa_decrypt_aes_key(encrypted_aes_key, private_key)
        with open('decrypted_aes_key.bin', 'wb') as f:
            f.write(aes_key)
    elif args.command == 'create_acl':
        create_acl(args.file, args.users)
    elif args.command == 'grant_access':
        grant_access(args.file, args.user, args.permission)
    elif args.command == 'verify':
        result = verify_integrity(args.file, args.hash)
        print('Integrity verified.' if result else 'Integrity compromised.')
    elif args.command == 'delete':
        secure_delete(args.file)
    else:
        print('Invalid command.')

if __name__ == '__main__':
    main()