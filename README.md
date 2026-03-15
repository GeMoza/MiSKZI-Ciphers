# MiSKZI-Ciphers

`MiSKZI-Ciphers` — учебный проект на Python по классическим шифрам. В репозитории собраны реализации с единым контрактом шифров, Streamlit UI и наборами вариантов из методичек в `data/*/variants.json`.

## Что есть в проекте

- реализованные шифры: `adfgvx`, `affine`, `alberti`, `atbash`, `bacon`, `binary_code`, `book_cipher`, `caesar`, `cardano_grille`, `gronsfeld`, `hill`, `litorea`, `magic_square`, `morse`, `polybius`, `ramsey`, `richelieu`, `scytale`, `trisemus`, `vernam`, `vigenere`;
- единый интерфейс `describe()/parse_key()/encrypt()/decrypt()` для всех шифров;
- Streamlit Playground для ручного запуска и проверки roundtrip;
- Data Manager для редактирования `variants.json` и `meta`;
- формат учебных данных `variants.json + meta`.

## Быстрый запуск

### 1. Создать окружение

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 2. Установить проект

```bash
python -m pip install -U pip
python -m pip install -e ".[ui,dev]"
```

### 3. Запустить UI

```bash
python -m streamlit run src/miskzi_ciphers/ui/app.py
```

### 4. Прогнать тесты

```bash
pytest -q
```

## Структура проекта

- `src/miskzi_ciphers/ciphers/` — реализации шифров
- `src/miskzi_ciphers/common/` — общие типы, registry и утилиты
- `src/miskzi_ciphers/app/service.py` — сервисный слой
- `src/miskzi_ciphers/ui/` — Streamlit UI
- `data/` — учебные варианты и метаданные
- `tests/` — автотесты
- `docs/` — подробная документация

## Документация

Подробная документация находится в [docs/README.md](docs/README.md).
