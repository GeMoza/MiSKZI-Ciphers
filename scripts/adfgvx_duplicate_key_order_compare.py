from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from miskzi_ciphers.ciphers.adfgvx.cipher import ADFGVXCipher, PAIR_TO_SYMBOL  # noqa: E402


def load_target_variants() -> list[dict[str, object]]:
    path = REPO_ROOT / "data" / "adfgvx" / "variants.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    wanted = {5, 8}
    return [item for item in raw["items"] if isinstance(item, dict) and item.get("id") in wanted]


def decode_stream(stream: str) -> str:
    if len(stream) % 2 != 0:
        return "<invalid: odd-length stream>"
    pairs = [stream[i : i + 2] for i in range(0, len(stream), 2)]
    if any(pair not in PAIR_TO_SYMBOL for pair in pairs):
        return "<invalid: unknown pair>"
    return "".join(PAIR_TO_SYMBOL[pair] for pair in pairs)


def occurrence_from_left(keyword: str) -> list[int]:
    seen: dict[str, int] = defaultdict(int)
    out: list[int] = []
    for ch in keyword:
        seen[ch] += 1
        out.append(seen[ch])
    return out


def occurrence_from_right(keyword: str) -> list[int]:
    seen: dict[str, int] = defaultdict(int)
    out = [0] * len(keyword)
    for i in range(len(keyword) - 1, -1, -1):
        ch = keyword[i]
        seen[ch] += 1
        out[i] = seen[ch]
    return out


def order_current(keyword: str) -> list[int]:
    return sorted(range(len(keyword)), key=lambda i: (keyword[i], i))


def order_duplicate_right_to_left(keyword: str) -> list[int]:
    return sorted(range(len(keyword)), key=lambda i: (keyword[i], -i))


def order_occurrence_numbered_left(keyword: str) -> list[int]:
    occ = occurrence_from_left(keyword)
    return sorted(range(len(keyword)), key=lambda i: (keyword[i], occ[i]))


def order_occurrence_numbered_right(keyword: str) -> list[int]:
    occ = occurrence_from_right(keyword)
    return sorted(range(len(keyword)), key=lambda i: (keyword[i], occ[i]))


def order_group_reversed(keyword: str) -> list[int]:
    groups: dict[str, list[int]] = defaultdict(list)
    for i, ch in enumerate(keyword):
        groups[ch].append(i)
    order: list[int] = []
    for ch in sorted(groups):
        order.extend(reversed(groups[ch]))
    return order


STRATEGIES = {
    "current": order_current,
    "duplicate-right-to-left": order_duplicate_right_to_left,
    "occurrence-numbered-left": order_occurrence_numbered_left,
    "occurrence-numbered-right": order_occurrence_numbered_right,
    "group-reversed": order_group_reversed,
}


def decrypt_with_order(ciphertext: str, keyword: str, order: list[int]) -> tuple[str, list[str]]:
    width = len(keyword)
    n = len(ciphertext)
    q, r = divmod(n, width)
    lengths = [q + (1 if i < r else 0) for i in range(width)]

    cols = [""] * width
    pos = 0
    for original_col in order:
        ln = lengths[original_col]
        cols[original_col] = ciphertext[pos : pos + ln]
        pos += ln

    rows_count = q + (1 if r else 0)
    out: list[str] = []
    for row in range(rows_count):
        for col in range(width):
            if row < len(cols[col]):
                out.append(cols[col][row])
    return "".join(out), cols


def main() -> None:
    cipher = ADFGVXCipher()
    print("ADFGVX duplicate-key ordering comparison")
    print()

    for item in load_target_variants():
        ciphertext = str(item["text"])
        keyword = cipher.parse_key(item["key"])["keyword"]
        print(f"variant {item['id']}")
        print(json.dumps({"ciphertext": ciphertext, "keyword": keyword}, ensure_ascii=False, indent=2))
        for name, fn in STRATEGIES.items():
            order = fn(keyword)
            stream, _cols = decrypt_with_order(ciphertext, keyword, order)
            decoded = decode_stream(stream)
            print(
                json.dumps(
                    {
                        "strategy": name,
                        "keyword": keyword,
                        "column_order": order,
                        "reconstructed_pair_stream": stream,
                        "decoded_result": decoded,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        print()


if __name__ == "__main__":
    main()
