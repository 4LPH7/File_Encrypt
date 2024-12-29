import os

def secure_delete(file_path, passes=3):
    with open(file_path, 'rb+') as f:
        length = f.seek(0, os.SEEK_END)
        f.seek(0)
        for _ in range(passes):
            f.write(os.urandom(length))
    os.remove(file_path)