from common.registry import list_ciphers, load_cipher

def build_min_raw_key_from_describe(info: dict) -> dict:
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
    return raw

def test_registry_contract_loads_and_validates_without_bad_parse_key_calls():
    for name in list_ciphers():
        c = load_cipher(name)
        info = c.describe()
        assert isinstance(info, dict)

        # Не делаем parse_key({}) вслепую.
        raw = build_min_raw_key_from_describe(info)
        key = c.parse_key(raw)

        # Минимальная проверка: методы существуют и возвращают строки
        s = "ТЕСТ"
        enc = c.encrypt(s, key)
        dec = c.decrypt(enc, key)
        assert isinstance(enc, str)
        assert isinstance(dec, str)
