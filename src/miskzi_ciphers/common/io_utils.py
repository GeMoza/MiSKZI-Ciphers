from __future__ import annotations
import json
from pathlib import Path
from miskzi_ciphers.common.types import Variant

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").rstrip("\n")

def load_variants(path: Path) -> list[Variant]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = []
    for v in raw.get("items", []):
        items.append(Variant(
            id=int(v["id"]),
            mode=str(v["mode"]),
            text=str(v["text"]),
            key=dict(v.get("key", {})),
            expected=(None if "expected" not in v else str(v["expected"])),
        ))
    return items
