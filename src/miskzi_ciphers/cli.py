from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from miskzi_ciphers.common.registry import load_cipher, list_ciphers
from miskzi_ciphers.common.io_utils import load_variants, read_text
from miskzi_ciphers.common.paths import get_data_dir


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="miskzi",
        description="Учебные шифры: encrypt/decrypt, варианты из методички, единый CLI.",
    )

    p.add_argument("--list-ciphers", action="store_true", help="Показать доступные шифры и выйти.")
    p.add_argument("--cipher", help="Имя шифра (например: caesar, scytale, ...).")

    p.add_argument("--describe", action="store_true", help="Показать параметры шифра и выйти.")
    p.add_argument("--list-variants", action="store_true", help="Показать варианты для шифра и выйти.")

    p.add_argument("--mode", choices=["encrypt", "decrypt"], help="Режим работы.")

    src = p.add_mutually_exclusive_group()
    src.add_argument("--text", help="Текст для обработки (строка).")
    src.add_argument("--text-file", help="Путь к файлу с текстом.")
    src.add_argument("--free", action="store_true", help="Взять data/<cipher>/free_text.txt.")
    src.add_argument("--variant", type=int, help="Взять data/<cipher>/variants.json по id.")

    p.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="K=V",
        help="Параметр ключа: K=V. Можно несколько раз: --key k=3 --key method=2",
    )

    p.add_argument("--out", help="Сохранить результат в файл вместо stdout.")
    p.add_argument("--json", action="store_true", help="Выводить JSON (актуально для --describe).")

    return p


def parse_cli_key(pairs: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in pairs:
        if "=" not in item:
            raise ValueError(f"Bad --key '{item}'. Use K=V.")
        k, v = item.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise ValueError(f"Bad --key '{item}'. Empty key name.")
        out[k] = v  # намеренно оставляем строковое значение; нормализация выполняется в cipher.parse_key()
    return out


def load_text_and_variant_key(data_dir: Path, cipher_name: str, variant_id: int) -> tuple[str, dict[str, Any], str]:
    variants_path = data_dir / cipher_name / "variants.json"
    variants = load_variants(variants_path)
    v = next((x for x in variants if x.id == variant_id), None)
    if v is None:
        ids = [x.id for x in variants]
        raise ValueError(f"Variant id={variant_id} not found. Available: {ids}")
    return v.text, dict(v.key), v.mode


def ensure_cipher_arg(cipher_name: str | None) -> str:
    if not cipher_name:
        raise ValueError("Missing --cipher. Use --list-ciphers to see available.")
    return cipher_name


def print_variants(data_dir: Path, cipher_name: str) -> None:
    variants_path = data_dir / cipher_name / "variants.json"
    variants = load_variants(variants_path)
    if not variants:
        print("(no variants)")
        return
    for v in variants:
        snippet = v.text.replace("\n", " ")
        if len(snippet) > 60:
            snippet = snippet[:57] + "..."
        print(f"{v.id:>3} | {v.mode:<7} | {snippet}")


def format_key_examples(info: dict, cipher_name: str) -> list[str]:
    params = info.get("params", []) or []

    required_pairs: list[str] = []
    for ps in params:
        if ps.get("required"):
            nm = ps.get("name")
            ex = ps.get("example", None)
            if nm and ex is not None:
                required_pairs.append(f"--key {nm}={ex}")

    examples: list[str] = []
    if required_pairs:
        examples.append(
            f"python main.py --cipher {cipher_name} --mode encrypt --text \"...\" " + " ".join(required_pairs)
        )

    all_pairs: list[str] = []
    for ps in params:
        nm = ps.get("name")
        if not nm:
            continue
        if "example" in ps:
            val = ps["example"]
        elif "default" in ps:
            val = ps["default"]
        else:
            continue
        all_pairs.append(f"--key {nm}={val}")

    if all_pairs and all_pairs != required_pairs:
        examples.append(
            f"python main.py --cipher {cipher_name} --mode decrypt --text \"...\" " + " ".join(all_pairs)
        )

    return examples


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    try:
        # 1) Глобальное действие: вывести список шифров
        if args.list_ciphers:
            for name in list_ciphers():
                print(name)
            return 0

        # 2) Действия, требующие шифр
        cipher_name = ensure_cipher_arg(args.cipher)
        cipher = load_cipher(cipher_name)

        # 2а) Описание шифра и выход
        if args.describe:
            info = cipher.describe()
            if args.json:
                print(json.dumps(info, ensure_ascii=False, indent=2))
                return 0

            title = info.get("title", cipher_name)
            family = info.get("family", "")
            print(f"{cipher_name} — {title}" + (f" [{family}]" if family else ""))

            params = info.get("params", []) or []
            if not params:
                print("Params: (none)")
            else:
                print("Params:")
                for ps in params:
                    nm = ps.get("name", "?")
                    tp = ps.get("type", "?")
                    req = "required" if ps.get("required") else "optional"
                    default = ps.get("default", None)
                    choices = ps.get("choices", None)
                    help_ = ps.get("help", "")
                    line = f"  - {nm} ({tp}, {req})"
                    if default is not None:
                        line += f", default={default!r}"
                    if choices:
                        line += f", choices={choices}"
                    if help_:
                        line += f" — {help_}"
                    print(line)

            examples = format_key_examples(info, cipher_name)
            if examples:
                print("Examples:")
                for ex in examples:
                    print(" ", ex)

            return 0

        # 2б) Вывести варианты и выход
        if args.list_variants:
            data_dir = get_data_dir()
            print_variants(data_dir, cipher_name)
            return 0

        # 3) Фактическое шифрование/расшифровка: источник сначала, потом режим
        variant_key: dict[str, Any] = {}
        variant_mode: str | None = None

        if args.text is not None:
            text = args.text
        elif args.text_file is not None:
            text = read_text(Path(args.text_file))
        elif args.free:
            data_dir = get_data_dir()
            text = read_text(data_dir / cipher_name / "free_text.txt")
        elif args.variant is not None:
            data_dir = get_data_dir()
            text, variant_key, variant_mode = load_text_and_variant_key(data_dir, cipher_name, args.variant)
        else:
            raise ValueError("Missing input source. Use one of: --text, --text-file, --free, --variant.")

        # Определение режима:
        # - CLI --mode имеет высший приоритет
        # - иначе, если вариант имеет режим, использем его
        # - иначе, требуем --mode
        mode = args.mode or variant_mode
        if not mode:
            raise ValueError("Missing --mode encrypt|decrypt (or provide --variant with mode in variants.json).")

        # Объединение ключей: вариант предоставляет значения по умолчанию, CLI их переопределям
        cli_key = parse_cli_key(args.key)
        raw_key = {**variant_key, **cli_key}

        # Однократная нормализация ключа (сырой ис CLI/вариантов -> нормализованный ключ для шифра)
        key = cipher.parse_key(raw_key)

        if mode == "encrypt":
            out = cipher.encrypt(text, key)
        else:
            out = cipher.decrypt(text, key)

        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
        else:
            sys.stdout.write(out + "\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
