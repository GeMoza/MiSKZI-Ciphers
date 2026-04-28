from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NormalizedText:
    text: str
    removed: list[dict[str, str | int]] = field(default_factory=list)
    replacements: list[dict[str, str | int]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class BigramItem:
    index: int
    value: str
    first_char: str
    second_char: str
    filler_inserted: bool = False
    filler_reason: str = ""
    source_indexes: list[int] = field(default_factory=list)


@dataclass
class BigramSplit:
    bigrams: list[BigramItem]
    notes: list[str] = field(default_factory=list)


def normalize_for_bigram(
    text: str,
    alphabet: str,
    replacements: dict[str, str] | None = None,
    remove_non_alphabet: bool = True,
) -> NormalizedText:
    replacements = replacements or {}
    normalized_chars: list[str] = []
    removed: list[dict[str, str | int]] = []
    replacement_records: list[dict[str, str | int]] = []
    notes: list[str] = []

    for position, original_char in enumerate(text):
        upper_char = original_char.upper()
        replacement_char = replacements.get(upper_char, upper_char)
        if replacement_char != upper_char:
            replacement_records.append(
                {"index": position, "source": upper_char, "replacement": replacement_char}
            )

        if replacement_char in alphabet:
            normalized_chars.append(replacement_char)
            continue

        if remove_non_alphabet:
            removed.append({"index": position, "source": original_char})
            continue

        normalized_chars.append(replacement_char)

    if replacement_records:
        notes.append("Some characters were replaced according to the selected alphabet policy.")
    if removed:
        notes.append("Some characters outside the selected alphabet were removed.")

    return NormalizedText(
        text="".join(normalized_chars),
        removed=removed,
        replacements=replacement_records,
        notes=notes,
    )


def split_into_bigrams(text: str, filler: str) -> BigramSplit:
    bigrams: list[BigramItem] = []
    notes: list[str] = []
    position = 0
    bigram_index = 1

    while position < len(text):
        first_char = text[position]
        next_position = position + 1

        if next_position >= len(text):
            bigrams.append(
                BigramItem(
                    index=bigram_index,
                    value=first_char + filler,
                    first_char=first_char,
                    second_char=filler,
                    filler_inserted=True,
                    filler_reason="odd_length",
                    source_indexes=[position],
                )
            )
            notes.append("Filler was appended to the last single character.")
            position += 1
            bigram_index += 1
            continue

        second_char = text[next_position]
        if first_char == second_char:
            bigrams.append(
                BigramItem(
                    index=bigram_index,
                    value=first_char + filler,
                    first_char=first_char,
                    second_char=filler,
                    filler_inserted=True,
                    filler_reason="repeated_character",
                    source_indexes=[position],
                )
            )
            notes.append("Filler was inserted between repeated characters.")
            position += 1
            bigram_index += 1
            continue

        bigrams.append(
            BigramItem(
                index=bigram_index,
                value=first_char + second_char,
                first_char=first_char,
                second_char=second_char,
                source_indexes=[position, next_position],
            )
        )
        position += 2
        bigram_index += 1

    return BigramSplit(bigrams=bigrams, notes=notes)

