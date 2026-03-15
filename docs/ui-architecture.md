# Архитектура UI

## Общая структура

UI реализован в `src/miskzi_ciphers/ui/app.py` на Streamlit. В приложении одна точка входа и две страницы:

- `Playground`
- `Data Manager`

Обе страницы работают с одним и тем же выбранным `cipher_id` через `st.session_state["ui_cipher_id"]`.

## Playground

Playground нужен для ручного запуска шифра. Основные шаги:

1. выбрать шифр;
2. посмотреть `describe()`;
3. ввести ключ в режиме Form или Raw JSON;
4. при необходимости загрузить вариант или `free_text`;
5. выполнить `Encrypt`, `Decrypt` или `Roundtrip`.

Playground хранит отдельные ключи состояния:

- `pg_plaintext`
- `pg_ciphertext`
- `pg_decrypted`
- `pg_key_raw_json`
- `pg_key_form_values`
- `pg_key_mode`
- `pg_feedback`
- `pg_loaded_source_type`
- `pg_loaded_variant_id`
- `pg_loaded_cipher_id`

## Data Manager

Data Manager редактирует `variants.json` для выбранного шифра. Он:

- показывает каталоги `data/` и `data/<cipher_id>/`;
- загружает и редактирует `meta`;
- отображает список вариантов;
- позволяет редактировать существующий вариант или добавить новый;
- валидирует данные перед сохранением;
- даёт быстро прогнать вариант через шифр.

## Роль `session_state`

`session_state` здесь не просто кэш, а фактическое хранилище промежуточного UI-состояния. Оно нужно, чтобы:

- не терять введённый ключ при перерисовке страницы;
- синхронизировать Form и Raw JSON;
- хранить контекст выбранного варианта;
- различать состояния разных шифров и режимов редактирования.

Поэтому строки-ключи в `session_state` — это часть инфраструктурного контракта UI.

## Режимы Form / Raw JSON

Обе страницы умеют работать с ключом в двух представлениях.

### Form

Форма строится динамически по `describe().params`. Тип поля (`int`, `bool`, `enum`, `str` и т.д.) определяет, какой Streamlit-виджет будет использован.

### Raw JSON

Пользователь редактирует сырой JSON-объект. Перед запуском или сохранением он:

- парсится как JSON;
- проверяется на то, что корень — объект;
- дополнительно прогоняется через `service.parse_key()`.

Это важно: `Raw JSON` не обходят контракт шифра, а лишь дают более прямой способ редактирования.

## Загрузка варианта

В Playground загрузка варианта работает так:

- UI берёт элемент из `items[]`;
- переносит `item["key"]` в form-state и raw JSON;
- переносит `item["text"]` либо в plaintext, либо в ciphertext в зависимости от `mode`;
- помечает источник как `variant`;
- показывает read-only feedback.

Сам файл при этом не меняется.

## Загрузка `free_text` и `raw_key_example`

Кнопка `Load free_text` в Playground:

- читает `meta.free_text`;
- подставляет его в plaintext;
- сбрасывает ciphertext/decrypted;
- если есть `meta.raw_key_example`, подставляет и его в ключ;
- если `raw_key_example` нет, очищает ключевую форму.

Это отдельный путь, не связанный с загрузкой конкретного `item`.

## Типовые риски Streamlit-state

Основные чувствительные места:

- один и тот же `ui_cipher_id` используется обеими страницами;
- при смене шифра нужно аккуратно очищать или пересобирать ключевые поля;
- form-state строится из динамических ключей вида `pg_key.<cipher>.<param>` и `dm.key_form.<ctx>.<param>`;
- несогласованность между `pg_key_form_values`, `pg_key_raw_json` и виджетами может приводить к "старым" значениям, если забыть синхронизацию.

Функции `_sync_key_form_widgets()`, `_clear_playground_key()`, `_ensure_widget_state()` и связанные helpers как раз существуют для удержания этого состояния в согласованном виде.

## Где что искать в коде

- инициализация состояния Playground — `_init_playground_state()`
- описание шифра и табличное представление параметров — `_show_description()`
- сбор ключа из формы — `_build_form_key()`
- парсинг Raw JSON — `_parse_raw_json()`
- загрузка варианта в Playground — `_on_load_variant()` и `_load_variant_into_playground()`
- загрузка `free_text` и `raw_key_example` — `_on_load_free_text()`
- кнопки `Encrypt/Decrypt/Roundtrip` — `_on_encrypt()`, `_on_decrypt()`, `_on_roundtrip()`
- редактирование `meta` и вариантов — `_data_manager()`

Важно не столько помнить каждую кнопку, сколько понимать разделение ответственности: UI держит состояние и вызывает сервис, а сервис уже обращается к registry, шифрам и данным.
