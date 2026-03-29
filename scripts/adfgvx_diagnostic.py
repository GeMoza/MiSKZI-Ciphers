from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from miskzi_ciphers.ciphers.adfgvx.cipher import ADFGVX, ADFGVXCipher, PAIR_TO_SYMBOL  # noqa: E402


def load_variants() -> dict[str, object]:
    path = REPO_ROOT / "data" / "adfgvx" / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def has_duplicate_letters(keyword: str) -> bool:
    letters = Counter(keyword)
    return any(count > 1 for count in letters.values())


def first_divergence_note(stream: str, pairs: list[str], decoded: str, duplicate_key: bool) -> str:
    if len(stream) % 2 != 0:
        return "pair stream became odd-length immediately after _columnar_decrypt"
    if any(pair not in PAIR_TO_SYMBOL for pair in pairs):
        return "first structural mismatch appears right after pair splitting"
    if duplicate_key:
        return "no structural mismatch inside current trace; first plausible risk zone is duplicate-key column ordering"
    if decoded.isalnum():
        return "no structural mismatch inside current trace; first visible divergence would be methodics-vs-output semantics after substitution"
    return "no structural mismatch inside current trace; first visible divergence is only at the final substituted text"


def trace_variant(cipher: ADFGVXCipher, item: dict[str, object]) -> dict[str, object]:
    ciphertext = str(item["text"])
    raw_keyword = str(item["key"]["keyword"])
    keyword = cipher.parse_key({"keyword": raw_keyword})["keyword"]
    width = len(keyword)
    n = len(ciphertext)
    q, r = divmod(n, width)
    lengths = [q + (1 if i < r else 0) for i in range(width)]
    order = cipher._sort_order(keyword)

    cols = [""] * width
    pos = 0
    for original_col in order:
        ln = lengths[original_col]
        cols[original_col] = ciphertext[pos : pos + ln]
        pos += ln

    stream = cipher._columnar_decrypt(ciphertext, keyword)
    pairs = [stream[i : i + 2] for i in range(0, len(stream), 2)]
    decoded = "".join(PAIR_TO_SYMBOL[p] for p in pairs) if len(stream) % 2 == 0 and all(p in PAIR_TO_SYMBOL for p in pairs) else "<invalid>"
    duplicate_key = has_duplicate_letters(keyword)

    return {
        "id": item["id"],
        "ciphertext": ciphertext,
        "keyword": keyword,
        "keyword_length": width,
        "ciphertext_length": n,
        "divmod": {"q": q, "r": r},
        "lengths": [{"col": i, "key_char": keyword[i], "length": lengths[i]} for i in range(width)],
        "sort_order": [{"sorted_pos": idx, "original_col": col, "key_char": keyword[col]} for idx, col in enumerate(order)],
        "columns": [{"col": i, "key_char": keyword[i], "slice": cols[i]} for i in range(width)],
        "reconstructed_pair_stream": stream,
        "pairs": pairs,
        "decoded_symbols": decoded,
        "ciphertext_length_multiple_of_keyword_length": r == 0,
        "keyword_has_duplicate_letters": duplicate_key,
        "pair_stream_structurally_correct": len(stream) % 2 == 0 and all(pair in PAIR_TO_SYMBOL for pair in pairs),
        "first_divergence_note": first_divergence_note(stream, pairs, decoded, duplicate_key),
    }


def main() -> None:
    variants = load_variants()
    cipher = ADFGVXCipher()

    print("ADFGVX diagnostic trace")
    print(f"source={REPO_ROOT / 'data' / 'adfgvx' / 'variants.json'}")
    print()

    items = [item for item in variants["items"] if isinstance(item, dict)]
    for item in items:
        trace = trace_variant(cipher, item)
        print(f"variant {trace['id']}")
        print(json.dumps(trace, ensure_ascii=False, indent=2))
        print()


if __name__ == "__main__":
    main()
