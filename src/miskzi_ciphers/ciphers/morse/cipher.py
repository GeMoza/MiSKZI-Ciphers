from __future__ import annotations

from miskzi_ciphers.common.types import CipherInfo, Key

# Русская азбука Морзе (учебный вариант) + базовые знаки препинания.
MORSE_MAP = {
    "А": ".-", "Б": "-...", "В": ".--", "Г": "--.", "Д": "-..", "Е": ".", "Ё": ".",
    "Ж": "...-", "З": "--..", "И": "..", "Й": ".---", "К": "-.-", "Л": ".-..", "М": "--",
    "Н": "-.", "О": "---", "П": ".--.", "Р": ".-.", "С": "...", "Т": "-", "У": "..-",
    "Ф": "..-.", "Х": "....", "Ц": "-.-.", "Ч": "---.", "Ш": "----", "Щ": "--.-", "Ъ": "--.--",
    "Ы": "-.--", "Ь": "-..-", "Э": "..-..", "Ю": "..--", "Я": ".-.-",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
    "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "-": "-....-", "!": "-.-.--", "?": "..--..", ":": "---...",
    ";": "-.-.-.", "(": "-.--.", ")": "-.--.-", "\"": ".-..-.", "'": ".----.", "/": "-..-.",
}
REVERSE_MORSE: dict[str, str] = {}
for ch, code in MORSE_MAP.items():
    REVERSE_MORSE.setdefault(code, ch)


class MorseCipher:
    name = "morse"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Азбука Морзе",
            "family": "encoding",
            "params": [],
            "notes": "Буквы разделяются пробелом, слова — '/'. Неизвестные коды при расшифровании заменяются на '?'.",
        }

    def parse_key(self, raw_key: Key) -> Key:
        if raw_key:
            raise ValueError("morse: this cipher does not use a key.")
        return {}

    def encrypt(self, plaintext: str, key: Key) -> str:
        words_out: list[str] = []
        for word in plaintext.split():
            letters: list[str] = []
            for ch in word:
                code = MORSE_MAP.get(ch.upper())
                letters.append(code if code is not None else "?")
            words_out.append(" ".join(letters))
        return " / ".join(words_out)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        normalized = ciphertext.replace(" / ", "/")
        words = [w.strip() for w in normalized.split("/")]

        out_words: list[str] = []
        for word in words:
            if not word:
                continue
            chars = [REVERSE_MORSE.get(token, "?") for token in word.split()]
            out_words.append("".join(chars))
        return " ".join(out_words)


def get_cipher() -> MorseCipher:
    return MorseCipher()
