from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from miskzi_ciphers.ciphers.adfgvx.cipher import ADFGVXCipher, PAIR_TO_SYMBOL  # noqa: E402


def load_variants() -> list[dict[str, object]]:
    path = REPO_ROOT / "data" / "adfgvx" / "variants.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [item for item in raw["items"] if isinstance(item, dict)]


def decode_stream(stream: str) -> str:
    if len(stream) % 2 != 0:
        return "<invalid: odd-length stream>"
    pairs = [stream[i : i + 2] for i in range(0, len(stream), 2)]
    if any(pair not in PAIR_TO_SYMBOL for pair in pairs):
        return "<invalid: unknown pair>"
    return "".join(PAIR_TO_SYMBOL[pair] for pair in pairs)


def experimental_columnar_decrypt(ciphertext: str, keyword: str, cipher: ADFGVXCipher) -> str:
    width = len(keyword)
    n = len(ciphertext)
    rows_count = (n + width - 1) // width
    filled = [[False] * width for _ in range(rows_count)]

    pos = 0
    for row in range(rows_count):
        for col in range(width):
            if pos < n:
                filled[row][col] = True
                pos += 1

    order = cipher._sort_order(keyword)
    table = [[""] * width for _ in range(rows_count)]

    pos = 0
    for col in order:
        for row in range(rows_count):
            if filled[row][col]:
                table[row][col] = ciphertext[pos]
                pos += 1

    out: list[str] = []
    for row in range(rows_count):
        for col in range(width):
            if filled[row][col]:
                out.append(table[row][col])
    return "".join(out)


def main() -> None:
    cipher = ADFGVXCipher()
    print("ADFGVX columnar decrypt comparison")
    print()

    for item in load_variants():
        ciphertext = str(item["text"])
        keyword = cipher.parse_key(item["key"])["keyword"]
        old_stream = cipher._columnar_decrypt(ciphertext, keyword)
        new_stream = experimental_columnar_decrypt(ciphertext, keyword, cipher)
        old_decoded = decode_stream(old_stream)
        new_decoded = decode_stream(new_stream)

        print(f"variant {item['id']}")
        print(
            json.dumps(
                {
                    "ciphertext": ciphertext,
                    "keyword": keyword,
                    "old_pair_stream": old_stream,
                    "new_pair_stream": new_stream,
                    "old_decoded": old_decoded,
                    "new_decoded": new_decoded,
                    "same_stream": old_stream == new_stream,
                    "same_decoded": old_decoded == new_decoded,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        print()


if __name__ == "__main__":
    main()
