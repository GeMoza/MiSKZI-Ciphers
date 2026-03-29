from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from miskzi_ciphers.app import service  # noqa: E402


def load_variants() -> list[dict[str, object]]:
    path = REPO_ROOT / 'data' / 'rubik_2x2' / 'variants.json'
    raw = json.loads(path.read_text(encoding='utf-8'))
    return [item for item in raw['items'] if isinstance(item, dict) and item.get('id') in {1, 2, 3}]


def main() -> None:
    print('rubik_2x2 methodics layout variants 1-3 diagnostic')
    print()

    for item in load_variants():
        result = service.run_variant('rubik_2x2', item)
        expected = item.get('expected', '')
        print(f"variant {item['id']}")
        print(
            json.dumps(
                {
                    'input_mode': item.get('input_mode'),
                    'layout': item.get('layout'),
                    'moves': item.get('key', {}).get('moves', []),
                    'current_result': result,
                    'expected_methodics_ciphertext': expected,
                    'matches_methodics': result == expected,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        print()


if __name__ == '__main__':
    main()
