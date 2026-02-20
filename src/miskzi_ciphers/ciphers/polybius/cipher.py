from __future__ import annotations

from miskzi_ciphers.common.keyparse import reject_unknown_keys, require, as_enum_int
from miskzi_ciphers.common.types import CipherInfo, Key


# Таблица из методички (рис. 3), координаты: (вертикальная = номер столбца 1..6, горизонтальная = номер строки 1..6)
TABLE = [
    ["А", "Б", "В", "Г", "Д", "Е"],
    ["Ё", "Ж", "З", "И", "Й", "К"],
    ["Л", "М", "Н", "О", "П", "Р"],
    ["С", "Т", "У", "Ф", "Х", "Ц"],
    ["Ч", "Ш", "Щ", "Ъ", "Ы", "Ь"],
    ["Э", "Ю", "Я", "_", ",", "."],
]
H = 6
W = 6

# map char -> (col, row), с нумерацией с 1
POS: dict[str, tuple[int, int]] = {}
for row in range(1, H + 1):
    for col in range(1, W + 1):
        POS[TABLE[row - 1][col - 1]] = (col, row)

# Поддержка строчных букв (в вариантах встречается)
POS_L: dict[str, tuple[int, int]] = {k.lower(): v for k, v in POS.items()}


def at(col: int, row: int) -> str:
    return TABLE[row - 1][col - 1]


class PolybiusCipher:
    name = "polybius"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Квадрат Полибия (методы 1/2/3, табл. 6×6)",
            "family": "substitution/fractionation",
            "params": [
                {
                    "name": "method",
                    "type": "int",
                    "required": True,
                    "choices": [1, 2, 3],
                    "help": "Метод 1/2/3 по методичке.",
                    "example": 1,
                }
            ],
            "notes": (
                "Метод 1: заменить букву на нижнюю в том же столбце (с циклическим переходом снизу вверх).\n"
                "Метод 2: буквы -> координаты (col,row), координаты записать вертикально (сначала все col, затем все row), "
                "прочитать по строкам (получить поток цифр), разбить на пары и снова по таблице в буквы.\n"
                "Метод 3: как метод 2, но поток цифр циклически сдвинуть влево на 1 (нечётное число шагов), "
                "потом разбить на пары и в буквы."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["method"], cipher=self.name)
        method = as_enum_int(require(raw_key, "method"), "method", {1, 2, 3})
        return {"method": method}

    def encrypt(self, plaintext: str, key: Key) -> str:
        m = key["method"]
        if m == 1:
            return self._m1_shift_down(plaintext)
        if m == 2:
            return self._m2_fractionate(plaintext)
        if m == 3:
            return self._m3_fractionate_shift(plaintext)
        raise ValueError("polybius: invalid method")

    def decrypt(self, ciphertext: str, key: Key) -> str:
        m = key["method"]
        if m == 1:
            return self._m1_shift_up(ciphertext)
        if m == 2:
            return self._m2_defractionate(ciphertext)
        if m == 3:
            return self._m3_defractionate_shift(ciphertext)
        raise ValueError("polybius: invalid method")

    @staticmethod
    def _pos(ch: str) -> tuple[int, int] | None:
        if ch in POS:
            return POS[ch]
        lo = ch.lower()
        if lo in POS_L:
            return POS_L[lo]
        return None

    @staticmethod
    def _case(ch: str, template: str) -> str:
        # если вход был в нижнем регистре — выводим нижний (для букв), для _,.,, оставляем как есть
        if template.islower() and ch.isalpha():
            return ch.lower()
        return ch

    # ---- Метод 1 ----
    def _m1_shift_down(self, s: str) -> str:
        out: list[str] = []
        for ch in s:
            p = self._pos(ch)
            if p is None:
                out.append(ch)
                continue
            col, row = p
            row2 = row + 1 if row < H else 1
            out.append(self._case(at(col, row2), ch))
        return "".join(out)

    def _m1_shift_up(self, s: str) -> str:
        out: list[str] = []
        for ch in s:
            p = self._pos(ch)
            if p is None:
                out.append(ch)
                continue
            col, row = p
            row2 = row - 1 if row > 1 else H
            out.append(self._case(at(col, row2), ch))
        return "".join(out)

    # ---- Метод 2 ----
    def _m2_fractionate(self, s: str) -> str:
        cols: list[int] = []
        rows: list[int] = []
        keep: list[tuple[int, str]] = []  # позиция среди ЗАКОДИРУЕМЫХ символов, символ который оставляем как есть

        enc_count = 0
        for ch in s:
            p = self._pos(ch)
            if p is None:
                keep.append((enc_count, ch))
                continue
            col, row = p
            cols.append(col)
            rows.append(row)
            enc_count += 1

        stream = "".join(str(x) for x in cols + rows)

        # В методичке примеры без вставок, но в вариантах может быть пунктуация — делаем обратимый формат:
        # digits|pos:char;pos:char...
        if keep:
            parts = []
            for pos, ch in keep:
                esc = ch.replace("\\", "\\\\").replace(";", "\\;").replace(":", "\\:").replace("|", "\\|")
                parts.append(f"{pos}:{esc}")
            stream = stream + "|" + ";".join(parts)

        return self._digits_to_letters(stream)

    def _m2_defractionate(self, s: str) -> str:
        letters, keep = self._split_keep(s)
        digits = self._letters_to_digits(letters)

        if len(digits) % 2 != 0:
            raise ValueError("polybius m2: invalid digit stream length")

        pairs = [digits[i : i + 2] for i in range(0, len(digits), 2)]
        # каждая пара -> (col,row)
        cols: list[int] = []
        rows: list[int] = []
        for pr in pairs:
            col = int(pr[0])
            row = int(pr[1])
            cols.append(col)
            rows.append(row)

        n = len(cols)
        if n % 2 != 0:
            # по теории может быть, но для корректной дефракции нужно чётное число пар?
            # фактически метод 2 из методички даёт столько же пар, сколько букв исходного текста.
            pass

        half = n // 2
        # метод 2: после шифрования получили пары из (cols+rows), значит при расшифровке делим пополам:
        c1 = cols[:half]
        c2 = cols[half:]
        r1 = rows[:half]
        r2 = rows[half:]

        # но нам нужен исходный (col,row) по позициям: col_i = stream[i], row_i = stream[i+N]
        # Проще: просто взять digits как поток, восстановить cols/rows:
        # digits = c[0..N-1] + r[0..N-1]
        # Здесь N = число букв исходного сообщения.
        # Значит N = len(digits)/2, cols = digits[:N], rows = digits[N:]
        N = len(digits) // 2
        cols0 = [int(x) for x in digits[:N]]
        rows0 = [int(x) for x in digits[N:]]

        out: list[str] = []
        for i in range(N):
            if i in keep:
                out.append(keep[i])
                continue
            out.append(at(cols0[i], rows0[i]))
        # хвостовые keep (на всякий)
        for k in sorted(pos for pos in keep.keys() if pos >= N):
            out.append(keep[k])
        return "".join(out)

    # ---- Метод 3 ----
    def _m3_fractionate_shift(self, s: str) -> str:
        # как m2, но потом циклический сдвиг digits влево на 1 (нечётный шаг)
        cols: list[int] = []
        rows: list[int] = []
        keep: list[tuple[int, str]] = []
        enc_count = 0
        for ch in s:
            p = self._pos(ch)
            if p is None:
                keep.append((enc_count, ch))
                continue
            col, row = p
            cols.append(col)
            rows.append(row)
            enc_count += 1

        digits = "".join(str(x) for x in cols + rows)
        if digits:
            digits = digits[1:] + digits[0]

        if keep:
            parts = []
            for pos, ch in keep:
                esc = ch.replace("\\", "\\\\").replace(";", "\\;").replace(":", "\\:").replace("|", "\\|")
                parts.append(f"{pos}:{esc}")
            digits = digits + "|" + ";".join(parts)

        return self._digits_to_letters(digits)

    def _m3_defractionate_shift(self, s: str) -> str:
        letters, keep = self._split_keep(s)
        digits = self._letters_to_digits(letters)
        if digits:
            # обратный сдвиг: вправо на 1
            digits = digits[-1] + digits[:-1]

        if len(digits) % 2 != 0:
            raise ValueError("polybius m3: invalid digit stream length")

        N = len(digits) // 2
        cols0 = [int(x) for x in digits[:N]]
        rows0 = [int(x) for x in digits[N:]]

        out: list[str] = []
        for i in range(N):
            if i in keep:
                out.append(keep[i])
                continue
            out.append(at(cols0[i], rows0[i]))
        for k in sorted(pos for pos in keep.keys() if pos >= N):
            out.append(keep[k])
        return "".join(out)

    # ---- вспомогательные методы ----
    def _digits_to_letters(self, s: str) -> str:
        # если есть keep-секция после | — обрабатываем только digits до |
        digits, keep = self._split_keep(s)
        if len(digits) % 2 != 0:
            raise ValueError("polybius: digit stream must have even length")
        out_letters: list[str] = []
        for i in range(0, len(digits), 2):
            col = int(digits[i])
            row = int(digits[i + 1])
            if not (1 <= col <= 6 and 1 <= row <= 6):
                raise ValueError(f"polybius: плохая координата {col}{row}")
            out_letters.append(at(col, row))

        # Снова добавим keep как обратимую часть, чтобы decrypt мог восстановить
        if keep:
            parts = []
            for pos, ch in keep.items():
                esc = ch.replace("\\", "\\\\").replace(";", "\\;").replace(":", "\\:").replace("|", "\\|")
                parts.append(f"{pos}:{esc}")
            return "".join(out_letters) + "|" + ";".join(parts)

        return "".join(out_letters)

    def _letters_to_digits(self, s: str) -> str:
        # Каждая буква таблицы -> 2 цифры (col,row)
        digits: list[str] = []
        for ch in s:
            p = self._pos(ch)
            if p is None:
                raise ValueError(f"polybius: character not in table: {ch!r}")
            col, row = p
            digits.append(str(col))
            digits.append(str(row))
        return "".join(digits)

    def _split_keep(self, s: str) -> tuple[str, dict[int, str]]:
        if "|" not in s:
            return s, {}
        a, b = s.split("|", 1)
        keep: dict[int, str] = {}
        if b.strip():
            for it in b.split(";"):
                if not it:
                    continue
                pos_s, ch_s = it.split(":", 1)
                pos = int(pos_s)
                # unescape
                ch = []
                j = 0
                while j < len(ch_s):
                    if ch_s[j] == "\\" and j + 1 < len(ch_s):
                        ch.append(ch_s[j + 1])
                        j += 2
                    else:
                        ch.append(ch_s[j])
                        j += 1
                keep[pos] = "".join(ch)
        return a, keep


def get_cipher() -> PolybiusCipher:
    return PolybiusCipher()
