from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from miskzi_ciphers.ciphers.rubik_2x2.cipher import ALL_POSITIONS, COMPLETE_RIGHT_TURN_MAPS, OUTPUT_STENCIL, Rubik2x2Cipher  # noqa: E402

FACE_ORDER = (1, 2, 3, 4, 5, 6)


def load_variant_1() -> dict[str, Any]:
    raw = json.loads((REPO_ROOT / "data" / "rubik_2x2" / "variants.json").read_text(encoding="utf-8"))
    for item in raw["items"]:
        if isinstance(item, dict) and item.get("id") == 1:
            return item
    raise RuntimeError("Variant 1 not found in data/rubik_2x2/variants.json")


def empty_state() -> dict[str, str]:
    return {position: "" for position in ALL_POSITIONS}


def format_letter(value: str) -> str:
    return value if value else "."


def format_state_grid(state: dict[str, str]) -> str:
    lines: list[str] = []
    for face in FACE_ORDER:
        tl = format_letter(state[f"{face}_tl"])
        tr = format_letter(state[f"{face}_tr"])
        bl = format_letter(state[f"{face}_bl"])
        br = format_letter(state[f"{face}_br"])
        lines.append(f"face {face}: [{tl} {tr}] [{bl} {br}]")
    return "\n".join(lines)


def format_occupied(state: dict[str, str]) -> str:
    occupied = [f"{position}={state[position]}" for position in ALL_POSITIONS if state[position]]
    return ", ".join(occupied) if occupied else "<none>"


def state_diff(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return [position for position in ALL_POSITIONS if before[position] != after[position]]


def moved_positions_from_permutation(permutation: dict[str, str]) -> list[str]:
    return [position for position in ALL_POSITIONS if permutation[position] != position]


def inverse_permutation(permutation: dict[str, str]) -> dict[str, str]:
    return {destination: source for source, destination in permutation.items()}


def apply_permutation(state: dict[str, str], permutation: dict[str, str]) -> dict[str, str]:
    next_state = empty_state()
    for source, destination in permutation.items():
        next_state[destination] = state[source]
    return next_state


def apply_move_once(state: dict[str, str], face: int, direction: str) -> tuple[dict[str, str], dict[str, str]]:
    right = COMPLETE_RIGHT_TURN_MAPS[face]
    permutation = inverse_permutation(right) if direction == "left" else right
    return apply_permutation(state, permutation), permutation


def read_output(state: dict[str, str]) -> str:
    return "".join(state[position] for position in OUTPUT_STENCIL)


def output_stencil_listing(state: dict[str, str]) -> list[str]:
    return [f"{position}={format_letter(state[position])}" for position in OUTPUT_STENCIL]


def main() -> None:
    cipher = Rubik2x2Cipher()
    item = load_variant_1()
    layout = cipher.parse_layout(item["layout"])
    moves = cipher.parse_key(item["key"])["moves"]
    expected = str(item["expected"])

    state = empty_state()
    state.update(layout)

    touched_by_move_map: set[str] = set()
    changed_by_content: set[str] = set()

    print("rubik_2x2 variant 1 step trace")
    print()
    print("variant data")
    print(json.dumps({"layout": layout, "moves": moves, "expected": expected}, ensure_ascii=False, indent=2))
    print()
    print("initial state")
    print(format_state_grid(state))
    print(f"occupied: {format_occupied(state)}")
    print()

    current = dict(state)
    for index, move in enumerate(moves, start=1):
        face = int(move["face"])
        direction = str(move["direction"])
        turns = int(move["turns"])

        print(f"after move {index}: face={face}, direction={direction}, turns={turns}")
        for turn_index in range(1, turns + 1):
            before_turn = dict(current)
            current, permutation = apply_move_once(current, face, direction)
            alt_direction = "left" if direction == "right" else "right"
            alt_state, alt_permutation = apply_move_once(before_turn, face, alt_direction)

            moved_now = moved_positions_from_permutation(permutation)
            changed_now = state_diff(before_turn, current)
            touched_by_move_map.update(moved_now)
            changed_by_content.update(changed_now)

            alt_moved_now = moved_positions_from_permutation(alt_permutation)
            alt_changed_now = state_diff(before_turn, alt_state)

            print(f"  turn {turn_index}")
            print(f"  moved positions by current permutation: {', '.join(moved_now) if moved_now else '<none>'}")
            print(f"  positions whose contents changed: {', '.join(changed_now) if changed_now else '<none>'}")
            print(f"  occupied after current direction: {format_occupied(current)}")
            print(format_state_grid(current))
            print(f"  diagnostic with inverted direction ({alt_direction}):")
            print(f"  moved positions by inverted permutation: {', '.join(alt_moved_now) if alt_moved_now else '<none>'}")
            print(f"  positions whose contents changed: {', '.join(alt_changed_now) if alt_changed_now else '<none>'}")
            print(f"  occupied after inverted direction: {format_occupied(alt_state)}")
            print(format_state_grid(alt_state))
        print()

    final_state = current
    readout = read_output(final_state)
    read_positions = output_stencil_listing(final_state)
    unread_occupied = [position for position in ALL_POSITIONS if final_state[position] and position not in OUTPUT_STENCIL]
    empty_output_cells = [position for position in OUTPUT_STENCIL if not final_state[position]]
    never_touched_by_move_map = [position for position in ALL_POSITIONS if position not in touched_by_move_map]
    never_changed_by_content = [position for position in ALL_POSITIONS if position not in changed_by_content]

    print("final state")
    print(format_state_grid(final_state))
    print(f"occupied: {format_occupied(final_state)}")
    print()
    print("final readout")
    print(f"OUTPUT_STENCIL order: {', '.join(OUTPUT_STENCIL)}")
    print(f"OUTPUT_STENCIL values: {', '.join(read_positions)}")
    print(f"current ciphertext: {readout!r}")
    print(f"expected ciphertext: {expected!r}")
    print(f"matches expected: {readout == expected}")
    print(f"occupied cells not read by OUTPUT_STENCIL: {', '.join(unread_occupied) if unread_occupied else '<none>'}")
    print(f"OUTPUT_STENCIL cells that are empty: {', '.join(empty_output_cells) if empty_output_cells else '<none>'}")
    print()
    print("touch summary")
    print("positions ever targeted by current move permutations: " + (", ".join(sorted(touched_by_move_map)) if touched_by_move_map else "<none>"))
    print("positions never targeted by current move permutations: " + (", ".join(never_touched_by_move_map) if never_touched_by_move_map else "<none>"))
    print("positions whose contents changed at least once: " + (", ".join(sorted(changed_by_content)) if changed_by_content else "<none>"))
    print("positions whose contents never changed: " + (", ".join(never_changed_by_content) if never_changed_by_content else "<none>"))


if __name__ == "__main__":
    main()

