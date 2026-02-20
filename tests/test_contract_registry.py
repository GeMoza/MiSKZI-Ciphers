from pathlib import Path

from miskzi_ciphers.common.registry import list_ciphers, load_cipher

def build_min_raw_key_from_describe(info: dict, cipher_name: str) -> dict:
    raw = {}
    for p in (info.get("params") or []):
        name = p.get("name")
        if not name:
            continue
        required = bool(p.get("required"))
        if not required:
            continue

        # Приоритет: example -> default -> типовой заглушкой
        if "example" in p:
            raw[name] = str(p["example"])
            continue
        if "default" in p:
            raw[name] = str(p["default"])
            continue

        t = (p.get("type") or "").lower()
        if t == "int":
            raw[name] = "1"
        elif t == "bool":
            raw[name] = "true"
        else:
            raw[name] = "x"
    if cipher_name == "book_cipher" and "key_text" not in raw and "key_path" not in raw:
        raw["key_path"] = str(Path("data") / "book_cipher" / "key.txt")
    return raw

def test_registry_contract_loads_and_validates_without_bad_parse_key_calls():
    for name in list_ciphers():
        c = load_cipher(name)
        info = c.describe()
        assert isinstance(info, dict)

        # Не делаем parse_key({}) вслепую.
        raw = build_min_raw_key_from_describe(info, name)
        key = c.parse_key(raw)

        # Минимальная проверка: методы существуют и возвращают строки
        sample = "ТЕСТ"
        if name == "magic_square":
            sample = "АБВГДЕЖЗИЙКЛМНОП"
        elif name == "scytale":
            sample = "ТЕСТТЕ"
        enc = c.encrypt(sample, key)
        dec = c.decrypt(enc, key)
        assert isinstance(enc, str)
        assert isinstance(dec, str)
