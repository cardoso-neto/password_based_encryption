"""
Fernet (AES CBC with random IV + HMAC SHA256 and PKCS7 padding) with password.

Key derived with PBKDF2HMAC: salted 100k times hashed (SHA3_256) password.
Inspired by https://stackoverflow.com/a/55147077/11615853
"""

import secrets
from base64 import urlsafe_b64decode as b64d
from base64 import urlsafe_b64encode as b64e
from typing import Tuple, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA3_256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


BACKEND = default_backend()
ITERATIONS = 100_000  # don't get too big here, OverflowError if >= 2 ** 32
Base64Bytes = bytes


class PWordFernet(Fernet):
    def __init__(
        self, password: str, encoding: str = "utf-8", iterations: int = ITERATIONS
    ):
        self.encoding = encoding
        self.iterations = iterations
        self.pword: bytes = password.encode(self.encoding)
        self.salt: bytes = secrets.token_bytes(16)
        self.key: Base64Bytes = self._derive_key(self.pword, self.salt)
        super().__init__(self.key)

    def _derive_key(
        self, password: bytes, salt: bytes, iterations: int = None
    ) -> Base64Bytes:
        """
        Derive a 32B secret key from a given password and salt and b64 encode it.    
        """
        if iterations is None:
            iterations = self.iterations
        kdf = PBKDF2HMAC(
            algorithm=SHA3_256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=BACKEND,
        )
        key = kdf.derive(password)
        return b64e(key)
        
    def encrypt(self, message: str) -> str:
        b_msg: bytes = message.encode(self.encoding)
        encrypted_msg = b64d(super().encrypt(b_msg))
        concat = self.salt + self.iterations.to_bytes(4, 'big') + encrypted_msg
        b64_cipher_text: str = b64e(concat).decode(self.encoding)
        return b64_cipher_text

    def decrypt(self, b64_cipher_text: Union[bytes, str]) -> str:
        cipher_text: bytes = b64d(b64_cipher_text)
        salt, iter_, encrypted_msg = self._split_cipher_text(cipher_text)
        iterations = int.from_bytes(iter_, "big")
        key = self._derive_key(self.pword, salt, iterations)
        b64_encrypted_msg = b64e(encrypted_msg)
        message: bytes = Fernet(key).decrypt(b64_encrypted_msg)
        decoded_msg: str = message.decode(self.encoding)
        return decoded_msg

    @staticmethod
    def _split_cipher_text(cipher_text) -> Tuple[bytes, bytes, bytes]:
        return cipher_text[:16], cipher_text[16:20], cipher_text[20:]
