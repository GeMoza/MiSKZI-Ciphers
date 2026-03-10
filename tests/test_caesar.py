from miskzi_ciphers.ciphers.caesar.cipher import CaesarCipher
from miskzi_ciphers.common.registry import load_cipher


def test_caesar_encrypt_example():
    c = CaesarCipher()
    key = c.parse_key({"k": 3})
    assert c.encrypt("ТЕСТ", key) == "ХЗФХ"


def test_caesar_decrypt_example():
    c = CaesarCipher()
    key = c.parse_key({"k": 3})
    assert c.decrypt("ХЗФХ", key) == "ТЕСТ"


def test_caesar_key_validation_missing():
    c = CaesarCipher()
    try:
        c.parse_key({})
        assert False, "Expected ValueError"
    except ValueError as e:
        assert "missing key 'k'" in str(e).lower()


def test_contract_roundtrip_with_raw_cli_key():
    c = load_cipher("caesar")
    key = c.parse_key({"k": "3"})
    out = c.encrypt("ТЕСТ", key)
    back = c.decrypt(out, key)
    assert back == "ТЕСТ"
