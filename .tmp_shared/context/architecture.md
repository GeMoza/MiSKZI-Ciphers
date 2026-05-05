# Architecture

## Invariants

- The project is an educational Python toolkit for classical ciphers and MiSKZI practice scenarios.
- Each cipher lives in `src/miskzi_ciphers/ciphers/<cipher_id>/cipher.py`.
- A cipher must expose `get_cipher()` or `CIPHER` and implement `name`, `describe()`, `parse_key()`, `encrypt()`, and `decrypt()`.
- `cipher.name`, the cipher package name, and `data/<cipher_id>/` must match.
- UI works through `src/miskzi_ciphers/app/service.py` rather than importing cipher modules directly.
- Variant data uses the root schema `{"meta": {...}, "items": [...]}`.

## Data Model

- Project metadata and variants are stored in `data/<cipher_id>/variants.json`.
- `meta` may include `free_text`, `notes`, and `raw_key_example`.
- `items` stores variant rows with `id`, `mode`, `key`, and either `text` or `layout`.
- `rubik_2x2` is the main special case with `input_mode = "layout"`.

## API / Interfaces

- CLI entrypoint: `miskzi = miskzi_ciphers.cli:main`.
- Registry entrypoints: `list_ciphers()` and `load_cipher()` from `common/registry.py`.
- Service layer provides `list_ciphers`, `get_cipher_description`, `parse_key`, `encrypt`, `decrypt`, `load_variants`, `save_variants`, and validation helpers.
- Streamlit UI lives in `src/miskzi_ciphers/ui/app.py` and has `Playground` and `Data Manager` pages.

## Decisions

- The repository favors a thin coordination layer in `app/service.py` and keeps cipher logic inside cipher packages.
- Registry autodiscovery is based on package scanning under `miskzi_ciphers.ciphers`.
- UI state is stored in Streamlit `session_state`, with form/raw JSON dual input modes for keys.

## Known Gaps

- The UI does not yet provide dedicated histogram and matrix-oriented educational views outside the practice layer.
- Some practice requirements explicitly note partial formalization and non-goals around exact legacy `.exe` compatibility.

## Notes

- Relevant sources: `README.md`, `pyproject.toml`, `docs/architecture-overview.md`, `docs/registry-and-loading.md`, `src/miskzi_ciphers/cli.py`, `src/miskzi_ciphers/app/service.py`, `src/miskzi_ciphers/common/registry.py`, `src/miskzi_ciphers/ui/app.py`.
