import env
import logging as log
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import Crypto.Random as Random
import base64

BLOCK_SIZE = 16


def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(
        BLOCK_SIZE - len(s) % BLOCK_SIZE
    )


def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


class Encrypter:
    def __init__(self) -> None:
        self.encryption_key = env.get_encryption_key()
        if self.encryption_key is None:
            log.warning("encryption key does not specified: using generated key")
            self.encryption_key = Random.get_random_bytes(32)
            log.debug(f"working with generated encryption key: {self.encryption_key}")
        else:
            self.encryption_key = SHA256.new(
                self.encryption_key.encode("utf-8")
            ).digest()
        log.info("encrypter has initialized")

    def encrypt(self, data: str) -> bytes:
        raw = str.encode(pad(data), encoding="utf-8")
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, data: bytes) -> str | None:
        try:
            enc = base64.b64decode(data)
            iv = enc[:16]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            return unpad(bytes.decode((cipher.decrypt(enc[16:])), encoding="utf-8"))
        except Exception:
            log.exception("can not decrypt data")
            return None
