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

- В реестр включены только реально существующие подпакеты в `src/miskzi_ciphers/ciphers/`; список дополнительно совпадает с `REGISTRY.list_names()`.
- `data = yes`, если найден `data/<cipher>/variants.json`.
- `vector tests = yes`, только если есть предметная проверка конкретного шифра на фиксированных входных/выходных данных; contract/smoke/roundtrip/UI-тесты не засчитываются.
- `ui i18n = yes`, если для `cipher_id` есть пользовательская подпись в `CIPHER_LABELS["ru"]`; при этом `DESC_OVERRIDES["ru"]` пуст, поэтому отдельные per-cipher override-описания сейчас не локализованы.
- `methodics = yes`, только если шифр явно отражён в `docs/methodics-mapping.md`.

| cipher_id | src | data | vector tests | ui i18n | methodics | notes |
| --- | --- | --- | --- | --- | --- | --- |
| `adfgvx` | yes | yes | no | yes | yes | В тестах есть только roundtrip. |
| `affine` | yes | yes | no | yes | yes | В методичках отмечен через рабочее сопоставление раннего блока ПЗ-2. |
| `alberti` | yes | yes | no | yes | yes |  |
| `atbash` | yes | yes | no | yes | yes | В `docs/methodics-mapping.md` фигурирует как пограничный ранний случай ПЗ-1/ПЗ-2. |
| `bacon` | yes | no | no | yes | yes | Есть только roundtrip в `tests/test_pz3_vectors.py`; `data/bacon/variants.json` отсутствует. |
| `binary_code` | yes | yes | no | yes | yes | В методичках отмечен через рабочее сопоставление раннего блока ПЗ-2. |
| `book_cipher` | yes | yes | no | yes | yes |  |
| `caesar` | yes | yes | yes | yes | yes | Фиксированные векторы есть в `tests/test_caesar.py`. |
| `cardano_grille` | yes | yes | no | yes | yes | Есть roundtrip/prefix-тест, но без фиксированного ожидаемого шифротекста. |
| `gronsfeld` | yes | yes | no | yes | yes | Есть только roundtrip в `tests/test_pz3_vectors.py`. |
| `hill` | yes | yes | yes | yes | yes | Методически относится к ПЗ-5, но фиксированный вектор живёт в `tests/test_pz4_vectors.py`. |
| `litorea` | yes | yes | no | yes | yes | В методичках отмечен через рабочее сопоставление раннего блока ПЗ-2. |
| `magic_square` | yes | yes | no | yes | yes |  |
| `morse` | yes | yes | no | yes | yes | Есть базовый encode/decode тест, но без фиксированного предметного вектора. |
| `polybius` | yes | yes | no | yes | yes |  |
| `ramsey` | yes | yes | yes | yes | yes | Фиксированные методические векторы есть в `tests/test_pz5_ramsey_vectors.py`. |
| `richelieu` | yes | yes | yes | yes | yes | Фиксированный вектор есть в `tests/test_pz4_vectors.py`. |
| `rubik_2x2` | yes | yes | yes | yes | yes | Фиксированные методические векторы есть в `tests/test_pz5_rubik_vectors.py`. |
| `scytale` | yes | yes | no | yes | yes |  |
| `trisemus` | yes | yes | no | yes | yes | Есть только roundtrip в `tests/test_pz3_vectors.py`. |
| `vernam` | yes | yes | no | yes | yes | Есть только roundtrip в `tests/test_pz4_vectors.py`. |
| `vigenere` | yes | yes | no | yes | yes | В `docs/methodics-mapping.md` отмечен как пограничный случай между ПЗ-2 и ПЗ-3; фиксированного вектора нет. |

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

- `rsa`
- `elgamal`
- `feistel_network`
- `magma`
- `rc5`
- `rc6`
- `kuznechik`
