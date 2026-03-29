from __future__ import annotations

import json
from pathlib import Path

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import load_cipher
from miskzi_ciphers.ui.i18n import CIPHER_LABELS


def _variants_json(cipher_id: str) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    path = data_dir / cipher_id / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_richelieu_variants_match_block_lengths_and_run() -> None:
    cipher = load_cipher("richelieu")
    variants = service.load_variants("richelieu")

    for item in variants["items"]:
        key = cipher.parse_key(item["key"])
        assert len(item["text"]) == sum(len(block) for block in key["permutations"])
        if item["mode"] == "encrypt":
            cipher.encrypt(item["text"], key)
        else:
            cipher.decrypt(item["text"], key)


def test_morse_corrected_variants_decode_to_expected_texts() -> None:
    cipher = load_cipher("morse")
    key = cipher.parse_key({})
    variants = {item["id"]: item for item in service.load_variants("morse")["items"]}

    assert cipher.decrypt(variants[1]["text"], key) == (
        "СЕРЫЕ ГЛАЗА - РАССВЕТ, ПАРОХОДНАЯ СИРЕНА, ДОЖДЬ, РАЗЛУКА, "
        "СЕРЫЙ СЛЕД ЗА ВИНТОМ БЕГУЩЕЙ ПЕНЫ."
    )
    assert cipher.decrypt(variants[4]["text"], key) == (
        "ЕСТЬ ЖЕНЩИНЫ В РУССКИХ СЕЛЕНЬЯХ С СПОКОЙНОЮ ВАЖНОСТЬЮ ЛИЦ, "
        "С КРАСИВОЮ СИЛОЙ В ДВИЖЕНЬЯХ, С ПОХОДКОЙ, СО ВЗГЛЯДОМ ЦАРИЦ."
    )
    assert cipher.decrypt(variants[7]["text"], key) == (
        "БЕЛЕЕТ ПАРУС ОДИНОКИЙ В ТУМАНЕ МОРЯ ГОЛУБОМ! "
        "ЧТО ИЩЕТ ОН В СТРАНЕ ДАЛЕКОЙ? ЧТО КИНУЛ ОН В КРАЮ РОДНОМ?"
    )
    assert cipher.decrypt(variants[10]["text"], key) == (
        "И СТРАННОЙ БЛИЗОСТЬЮ ЗАКОВАННЫЙ, СМОТРЮ ЗА ТЕМНУЮ ВУАЛЬ, "
        "И ВИЖУ БЕРЕГ ОЧАРОВАННЫЙ И ОЧАРОВАННУЮ ДАЛЬ."
    )


def test_vernam_raw_key_example_is_parseable_and_nontrivial() -> None:
    variants = service.load_variants("vernam")
    meta = variants["meta"]
    raw_key = meta["raw_key_example"]

    parsed = service.parse_key("vernam", raw_key)
    plaintext = meta["free_text"]
    ciphertext = service.encrypt("vernam", plaintext, raw_key)

    assert parsed == {"keyword": "ШИФР", "apply_to": "all"}
    assert ciphertext != plaintext
    assert service.decrypt("vernam", ciphertext, raw_key) == plaintext


def test_adfgvx_matches_methodical_example_from_pz4() -> None:
    key = {"keyword": "DRIVE"}

    assert service.encrypt("adfgvx", "UNIVERSITY", key) == "GFAFFAFDFGVXFDFGGDGG"
    assert service.decrypt("adfgvx", "GFAFFAFDFGVXFDFGGDGG", key) == "UNIVERSITY"


def test_hill_variants_file_contains_10_methodical_items_and_valid_vectors() -> None:
    variants = service.load_variants("hill")
    assert service.validate_variants_obj(variants) == []
    assert len(variants["items"]) == 10

    for item in variants["items"]:
        assert item["mode"] == "encrypt"
        assert service.encrypt("hill", item["text"], item["key"]) == item["expected"]


def test_ramsey_label_and_variants_match_current_methodical_set() -> None:
    variants = service.load_variants("ramsey")
    assert CIPHER_LABELS["ru"]["ramsey"] == "Шифр Рамзая"
    assert len(variants["items"]) == 10

    expected_by_id = {
        5: "19406 82839 79456 94468 29496 1435",
        6: "62948 32940 29632 73945 94925 99282 4",
        7: "62948 74358 89469 83947 39109 46294 02963 273",
        8: "69839 49224 87183 83379 49248 21694 10945 93915 97094 69839 40913 36306",
        9: "62940 59939 45940 35694 92249 40296 3273",
        10: "62294 96579 79480 22880 94085 21939 46983 94874 2698",
    }

    for item in variants["items"]:
        if item["id"] in expected_by_id:
            assert service.encrypt("ramsey", item["text"], item["key"]) == expected_by_id[item["id"]]


def test_rubik_current_key_examples_are_parseable_in_current_repo_state() -> None:
    variants = _variants_json("rubik_2x2")
    cipher = load_cipher("rubik_2x2")

    assert cipher.parse_key(variants["meta"]["raw_key_example"]) == variants["meta"]["raw_key_example"]
    for item in variants["items"]:
        assert cipher.parse_key(item["key"]) == item["key"]
