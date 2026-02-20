from miskzi_ciphers.ciphers.caesar.cipher import CaesarCipher
from miskzi_ciphers.common.registry import load_cipher

def test_caesar_encrypt_example():
    c = CaesarCipher()
    key = c.parse_key({"k": 3})
    assert c.encrypt("МИРЭА", key) == "ПЛУАГ"

def test_caesar_decrypt_example():
    c = CaesarCipher()
    key = c.parse_key({"k": 3})
    assert c.decrypt("ПЛУАГ", key) == "МИРЭА"

def test_caesar_key_validation_missing():
    c = CaesarCipher()
    try:
        c.parse_key({})
        assert False, "Expected ValueError"
    except ValueError as e:
        assert "missing key 'k'" in str(e).lower()

def test_contract_roundtrip_with_raw_cli_key():
    c = load_cipher("caesar")
    key = c.parse_key({"k": "3"})  # как из CLI: строка
    out = c.encrypt("МИРЭА", key)
    back = c.decrypt(out, key)
    assert back == "МИРЭА"
