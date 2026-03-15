# Документация MiSKZI-Ciphers

`MiSKZI-Ciphers` — учебный Python-проект по классическим шифрам. В репозитории собраны реализации шифров с единым контрактом, сервисный слой, Streamlit UI и набор учебных данных в `data/*/variants.json`.

## Карта документации

- [architecture-overview.md](architecture-overview.md) — общая архитектура и инварианты.
- [cipher-contract.md](cipher-contract.md) — обязательный контракт шифра и требования к `describe()/parse_key()/encrypt()/decrypt()`.
- [registry-and-loading.md](registry-and-loading.md) — автопоиск и загрузка шифров через `common/registry.py`.
- [data-format.md](data-format.md) — формат `data/<cipher>/variants.json`, роль `meta` и проверка структуры.
- [ui-architecture.md](ui-architecture.md) — устройство Streamlit UI, `session_state`, Playground и Data Manager.
- [localization.md](localization.md) — как устроены UI-строки и подписи параметров.
- [testing-strategy.md](testing-strategy.md) — какие тесты есть и что именно они страхуют.
- [adding-a-new-cipher.md](adding-a-new-cipher.md) — практический гайд по добавлению нового шифра.
- [methodics-mapping.md](methodics-mapping.md) — сопоставление кодовой базы с локальными методичками.
- [known-issues.md](known-issues.md) — ограничения и спорные места, которые важно знать до правок.
- [changelog.md](changelog.md) — краткая история последних значимых изменений.
- [pdf/README.md](pdf/README.md) — правила для локальной папки с PDF-методичками.

## Рекомендованный порядок чтения

1. [architecture-overview.md](architecture-overview.md)
2. [data-format.md](data-format.md)
3. [ui-architecture.md](ui-architecture.md)
4. [testing-strategy.md](testing-strategy.md)
5. [cipher-contract.md](cipher-contract.md)
6. [registry-and-loading.md](registry-and-loading.md)
7. [adding-a-new-cipher.md](adding-a-new-cipher.md)

## Что читать новичку

Если нужно быстро войти в проект, начните с [architecture-overview.md](architecture-overview.md), затем прочитайте [ui-architecture.md](ui-architecture.md) и [data-format.md](data-format.md). Этого достаточно, чтобы понять путь данных от UI до шифра и структуру учебных вариантов.

## Что читать перед добавлением нового шифра

Перед новой реализацией обязательно прочитайте:

1. [cipher-contract.md](cipher-contract.md)
2. [registry-and-loading.md](registry-and-loading.md)
3. [adding-a-new-cipher.md](adding-a-new-cipher.md)
4. [testing-strategy.md](testing-strategy.md)

## Про `docs/pdf/`

В `docs/pdf/` можно хранить локальные копии методичек и вспомогательные PDF для работы над проектом. Эта папка считается справочной: структура каталога сохраняется в репозитории, а новые локальные PDF по возможности не должны попадать в git. В рабочем дереве при этом уже могут присутствовать локальные копии методичек, на которые ссылается документация.
