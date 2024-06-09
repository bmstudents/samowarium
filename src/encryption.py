import env
import logging as log
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import Crypto.Random as Random
import base64

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(
    BLOCK_SIZE - len(s) % BLOCK_SIZE
)
unpad = lambda s: s[: -ord(s[len(s) - 1 :])]


class Encrypter:
    def __init__(self) -> None:
        if env.is_prod_profile():
            self.encryption_key = env.get_encryption_key_and_hide()
        else:
            self.encryption_key = env.get_encryption_key()
        if self.encryption_key is None:
            log.warning("encryption key does not specified: using generated key")
            self.encryption_key = Random.get_random_bytes(32)
            log.debug(f"working with generated encryption key: {self.encryption_key}")
        else:
            self.encryption_key = SHA256.new(
                self.encryption_key.encode("utf-8")
            ).digest()
        log.info("encrypter initialized")

    def encrypt(self, data: str) -> bytes:
        raw = str.encode(pad(data))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, data: bytes) -> str:
        enc = base64.b64decode(data)
        iv = enc[:16]
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))