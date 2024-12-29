import hashlib

def verify_integrity(file_path, expected_hash):
    with open(file_path, 'rb') as f:
        data = f.read()
    file_hash = hashlib.sha256(data).hexdigest()
    return file_hash == expected_hash