import os
import bcrypt
from Crypto.Protocol.KDF import PBKDF2
from encryption import generate_rsa_key_pair

def derive_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key, salt

def save_rsa_keys(public_key, private_key, filename):
    with open(f'{filename}_public.pem', 'wb') as f:
        f.write(public_key)
    with open(f'{filename}_private.pem', 'wb') as f:
        f.write(private_key)

def load_rsa_keys(public_file, private_file):
    with open(public_file, 'rb') as f:
        public_key = f.read()
    with open(private_file, 'rb') as f:
        private_key = f.read()
    return public_key, private_key