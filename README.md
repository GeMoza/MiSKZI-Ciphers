# MiSKZI-Ciphers

`MiSKZI-Ciphers` — учебный проект на Python по классическим шифрам. В репозитории собраны реализации с единым контрактом шифров, Streamlit UI и наборами вариантов из методичек в `data/*/variants.json`.

## Что есть в проекте

- реализованные шифры: `adfgvx`, `affine`, `alberti`, `atbash`, `bacon`, `binary_code`, `book_cipher`, `caesar`, `cardano_grille`, `gronsfeld`, `hill`, `litorea`, `magic_square`, `morse`, `polybius`, `ramsey`, `richelieu`, `rubik_2x2`, `scytale`, `trisemus`, `vernam`, `vigenere`;
- единый интерфейс `describe()/parse_key()/encrypt()/decrypt()` для всех шифров;
- Streamlit Playground для ручного запуска и проверки roundtrip;
- Data Manager для редактирования `variants.json` и `meta`;
- формат учебных данных `variants.json + meta`;
- локальные PDF-методички в `docs/pdf/` для сверки покрытия по практическим занятиям.

## Быстрый запуск

### 1. Подготовить окружение

```bash
python -m venv .venv
```

Затем активируйте окружение подходящей для вашей платформы командой:

- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- Windows cmd: `.venv\Scripts\activate.bat`
- Linux/macOS: `source .venv/bin/activate`

Если вы используете conda, можно создать и активировать отдельное окружение с Python 3.11 вместо `venv`.
Проект не требует конкретного имени окружения.

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
python -m pytest
```

Текущий `pytest` настроен через `pyproject.toml`, а тесты, которым нужны временные каталоги, используют локальный временный каталог внутри рабочего дерева проекта. Поэтому базовая команда одинакова для Windows, Linux и macOS.

Нюанс для Windows:

- если системные каталоги `%TEMP%`/`%TMP%` недоступны или ограничены политиками доступа, запуск через `python -m pytest` всё равно должен работать, потому что файловые тесты не зависят от системного tmp-каталога;
- если вы запускаете тесты вне корня репозитория, сначала перейдите в каталог проекта, иначе локальный временный каталог и пути из `tests/conftest.py` будут вычислены относительно другого места.

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
