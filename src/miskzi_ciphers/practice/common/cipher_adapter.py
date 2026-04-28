from __future__ import annotations

from typing import Any

from miskzi_ciphers.app import service


def run_cipher(cipher_id: str, operation: str, text: str, raw_key: dict[str, Any]) -> str:
    if operation == "encrypt":
        return service.encrypt(cipher_id, text, raw_key)
    if operation == "decrypt":
        return service.decrypt(cipher_id, text, raw_key)
    raise ValueError("operation must be 'encrypt' or 'decrypt'.")
