import hashlib


def hash_secret_key(secretKey: str) -> str:
    digest = hashlib.sha256()
    digest.update(secretKey.encode("utf-8"))
    return digest.hexdigest()
