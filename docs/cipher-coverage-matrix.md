# Матрица покрытия шифров

Документ фиксирует фактическое покрытие по текущему состоянию репозитория.

Проверенные источники:

- `src/miskzi_ciphers/ciphers/`
- `src/miskzi_ciphers/common/registry.py`
- `data/`
- `tests/`
- `src/miskzi_ciphers/ui/i18n.py`
- `docs/methodics-mapping.md`

Правила учёта:

- Таблица включает как реально существующие `cipher_id` из `src/miskzi_ciphers/ciphers/`, так и отдельные шифры/темы, которые уже встречаются в локальных методичках, но пока не реализованы в коде.
- Для реализованных шифров список `src = yes` дополнительно совпадает с `REGISTRY.list_names()`.
- `data = yes`, если найден `data/<cipher>/variants.json`.
- `vector tests = yes`, только если есть предметная проверка конкретного шифра на фиксированных входных/выходных данных; contract/smoke/roundtrip/UI-тесты не засчитываются.
- `ui i18n = yes`, если для `cipher_id` есть пользовательская подпись в `CIPHER_LABELS["ru"]`; при этом `DESC_OVERRIDES["ru"]` пуст, поэтому отдельные per-cipher override-описания сейчас не локализованы.
- `methodics = yes`, только если шифр явно отражён в `docs/methodics-mapping.md`.

| cipher_id | src | data | vector tests | ui i18n | methodics | notes |
| --- | --- | --- | --- | --- | --- | --- |
| `adfgvx` | yes | yes | no | yes | yes | В тестах есть только roundtrip; используется фиксированная таблица 24 из методички, а не произвольный квадрат. |
| `affine` | yes | yes | no | yes | yes | В методичках отмечен через рабочее сопоставление раннего блока ПЗ-2; реализация работает по русскому алфавиту. |
| `alberti` | yes | yes | no | yes | yes |  |
| `atbash` | yes | yes | no | yes | yes | В `docs/methodics-mapping.md` фигурирует как пограничный ранний случай ПЗ-1/ПЗ-2; используется русский алфавит. |
| `bacon` | yes | no | no | yes | yes | Есть только roundtrip в `tests/test_pz3_vectors.py`; `data/bacon/variants.json` отсутствует; используется RU_33-адаптация с 6-битным A/B-кодом. |
| `binary_code` | yes | yes | no | yes | yes | В методичках отмечен через рабочее сопоставление раннего блока ПЗ-2; это учебная тема кодирования, а не классический исторический шифр. |
| `book_cipher` | yes | yes | no | yes | yes |  |
| `caesar` | yes | yes | yes | yes | yes | Фиксированные векторы есть в `tests/test_caesar.py`; реализация работает по `RU_33`. |
| `cardano_grille` | yes | yes | no | yes | yes | Есть roundtrip/prefix-тест, но без фиксированного ожидаемого шифротекста; используется учебная маска из проекта. |
| `elgamal` | yes | yes | yes | yes | yes | Реализована учебная схема из ПЗ-06; `parse_key()` вычисляет y, а векторы зафиксированы в `tests/test_pz6_public_key_vectors.py`. |
| `feistel_network` | yes | yes | yes | yes | yes | Реализована учебная 4-раундовая схема из ПЗ-07; шифротекст хранится как 4 десятичных байта, а пример/варианты совпадают только при нумерации русского алфавита без `Ё`. |
| `gronsfeld` | yes | yes | no | yes | yes | Есть только roundtrip в `tests/test_pz3_vectors.py`; реализация работает по русскому алфавиту. |
| `hill` | yes | yes | yes | yes | yes | Методически относится к ПЗ-5, но фиксированный вектор живёт в `tests/test_pz4_vectors.py`; используется mod 33 и `RU_33` с `Ё`. |
| `kuznechik` | no | no | no | no | yes | Есть в ПЗ-7, но реализации, данных, UI-меток и тестов пока нет. |
| `litorea` | yes | yes | no | yes | yes | В методичках отмечен через рабочее сопоставление раннего блока ПЗ-2; это специфически русская историческая схема. |
| `magma` | yes | yes | yes | yes | yes | Реализован минимальный учебный core-блок Магмы на одном 64-битном hex-блоке; локальная ПЗ-07 даёт только теорию, поэтому data/tests содержат project control set, а не методические варианты. |
| `magic_square` | yes | yes | no | yes | yes |  |
| `morse` | yes | yes | no | yes | yes | Есть базовый encode/decode тест, но без фиксированного предметного вектора; используется русская азбука Морзе. |
| `polybius` | yes | yes | no | yes | yes |  |
| `ramsey` | yes | yes | yes | yes | yes | Фиксированные методические векторы есть в `tests/test_pz5_ramsey_vectors.py`; таблицы/ключевые слова жёстко фиксированы ПЗ-05. |
| `rc5` | yes | yes | yes | yes | yes | Реализована упрощённая учебная версия из ПЗ-07 на одном раунде; локальная методичка даёт подтверждённый пример, но не даёт отдельной таблицы вариантов, а страница 92 содержит аномалию в коде буквы `Л`. |
| `rc6` | yes | yes | yes | yes | yes | Реализована упрощённая учебная версия из ПЗ-07 на одном раунде с параметром циклического сдвига; данные покрывают пример и варианты 1–10 в raw-формате hex-байтов. |
| `richelieu` | yes | yes | yes | yes | yes | Фиксированный вектор есть в `tests/test_pz4_vectors.py`. |
| `rsa` | yes | yes | yes | yes | yes | Реализована учебная RSA-схема на малых числах; локальная ПЗ-06 даёт теорию без явной таблицы вариантов, поэтому в проекте зафиксирован минимальный учебный набор в `data/rsa/variants.json`. |
| `rubik_2x2` | yes | yes | yes | yes | yes | Фиксированные методические векторы есть в `tests/test_pz5_rubik_vectors.py`; используется учебная развёртка 2x2 из ПЗ-05. |
| `scytale` | yes | yes | no | yes | yes |  |
| `trisemus` | yes | yes | no | yes | yes | Есть только roundtrip в `tests/test_pz3_vectors.py`. |
| `vernam` | yes | yes | no | yes | yes | Есть только roundtrip в `tests/test_pz4_vectors.py`; реализован как учебная XOR-схема по `RU_33 + '.'`, а не общий байтовый OTP. |
| `vigenere` | yes | yes | no | yes | yes | В `docs/methodics-mapping.md` отмечен как пограничный случай между ПЗ-2 и ПЗ-3; фиксированного вектора нет; используется русский алфавит. |

## Реализованы, но без `data/`

- `bacon`

## Реализованы, но без предметных векторных тестов

- `adfgvx`
- `affine`
- `alberti`
- `atbash`
- `bacon`
- `binary_code`
- `book_cipher`
- `cardano_grille`
- `gronsfeld`
- `litorea`
- `magic_square`
- `morse`
- `polybius`
- `scytale`
- `trisemus`
- `vernam`
- `vigenere`

## Есть в методичках, но пока не реализованы

- `kuznechik`
