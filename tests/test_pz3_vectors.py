from __future__ import annotations

from miskzi_ciphers.common.registry import load_cipher


def test_gronsfeld_roundtrip() -> None:
    cipher = load_cipher("gronsfeld")
    key = cipher.parse_key({"digits": "15215"})
    plaintext = "МИРЭА"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_trisemus_roundtrip() -> None:
    cipher = load_cipher("trisemus")
    key = cipher.parse_key({"keyword": "КЛЮЧ", "cols": 6, "extras": "123"})
    plaintext = "МИРЭА"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_bacon_roundtrip() -> None:
    cipher = load_cipher("bacon")
    key = cipher.parse_key({"group_len": 6, "separator": " "})
    plaintext = "МИРЭА"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_cardano_grille_roundtrip_prefix() -> None:
    cipher = load_cipher("cardano_grille")
    key = cipher.parse_key({"size": 6, "rotation": "ccw", "filler": "А", "mask_id": "fig12"})
    plaintext = "МИРЭА"
    decrypted = cipher.decrypt(cipher.encrypt(plaintext, key), key)
    assert decrypted.startswith(plaintext)
