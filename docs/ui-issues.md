# UI issues

Документ фиксирует результаты кодового аудита UI-логики без ручного запуска Streamlit.

Проверенные источники:

- `src/miskzi_ciphers/ui/app.py`
- `src/miskzi_ciphers/ui/i18n.py`
- `src/miskzi_ciphers/app/service.py`
- `src/miskzi_ciphers/ciphers/`
- `data/*/variants.json`

## Confirmed issues

- В ходе аудита были исправлены две подтверждённые проблемы:
  - Form/Raw JSON могли расходиться по состоянию виджетов после ввода JSON-ключа, потому что parsed key не принудительно синхронизировал form-state.
  - Data Manager позволял сохранить `meta.raw_key_example` как JSON-объект корректного типа, но без проверки через `parse_key()`, из-за чего в данные можно было записать заведомо невалидный пример ключа.
- Остаётся один неблокирующий, но подтверждённый дефект полноты описаний:
  - часть `describe().params` не содержит `example`, а у части параметров нет и `help`, из-за чего таблица параметров и form-подсказки остаются неполными;
  - фактически это затрагивает `alberti.outer`, `alberti.inner`, `alberti.index_char`, `alberti.shift_every`, `alberti.shift_step`, `alberti.shift_dir`, `alberti.emit_prefix`, `alberti.start_outer`, `book_cipher.key_text`, `book_cipher.key_path`, `book_cipher.e_instead_of_ee`, `hill.pad_char`, `richelieu.permutations`, `vernam.apply_to`.

## Requires manual verification

- Визуальное поведение Playground после переключения между `Form` и `Raw JSON`: код теперь синхронизирует состояния, но фактическое отображение виджетов в Streamlit нужно подтвердить вручную.
- Визуальное поведение Data Manager после `Apply JSON to Form`: по коду значения формы синхронизируются, но фактическое обновление контролов в интерфейсе требует ручной проверки.
- Отрисовка таблицы параметров в `st.table(...)` для всех шифров: по коду значения сериализуются в строки и не содержат вложенных структур, но визуальную читаемость и переносы нужно проверять вручную.
- Удобство ввода JSON-параметров (`hill.matrix`, `rubik_2x2.moves`) в текстовых полях формы: логически это поддержано через `parse_key()`, но UX без ручного прогона оценить нельзя.
- Полный интерактивный сценарий редактирования и сохранения `variants.json`/`meta` в Data Manager: сервисный слой и сериализация проверены, но реальное поведение кнопок, rerun и сообщений интерфейса требует ручной проверки.
