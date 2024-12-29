import unittest
from encryption import aes_encrypt_file, aes_decrypt_file
import os

class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.test_file = 'test.txt'
        self.key = os.urandom(32)
        with open(self.test_file, 'w') as f:
            f.write('This is a test file.')

    def test_aes_encrypt_decrypt(self):
        aes_encrypt_file(self.test_file, self.key)
        self.assertTrue(os.path.exists(f'{self.test_file}.enc'))
        aes_decrypt_file(f'{self.test_file}.enc', self.key)
        with open(self.test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, 'This is a test file.')

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(f'{self.test_file}.enc'):
            os.remove(f'{self.test_file}.enc')

if __name__ == '__main__':
    unittest.main()