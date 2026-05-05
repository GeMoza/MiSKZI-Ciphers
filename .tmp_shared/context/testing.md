# Testing

## Invariants

- Tests cover multiple layers: registry and contract, service behavior, data schema, UI localization, and selected vector suites.
- `python -m pytest` is the default validation command described by project docs.
- Variant files are validated structurally and, for some cases, behaviorally through service and vector tests.

## Coverage Map

- Contract and registry: `test_ciphers_contract.py`, `test_contract_registry.py`.
- Service and paths: `test_service.py`, `test_paths.py`.
- Data schema: `test_variants_schema.py`, `test_variants_meta.py`.
- UI and localization: `test_ui_i18n.py`, `test_ui_localization_labels.py`, `test_ui_app.py`.
- Practice and vector coverage includes PR-focused tests such as `test_pz4_vectors.py`, `test_pz5_ramsey_vectors.py`, `test_practice_10_playfair.py`, `test_pz7_*`, and UI regression coverage.

## Validation Focus

- New cipher implementations should preserve registry discovery and the base cipher contract.
- Data changes should preserve `variants.json` schema and `parse_key()` compatibility for stored keys.
- UI changes should keep localization labels and key form/raw JSON synchronization stable.

## Known Gaps

- Existing contract tests are strong for infrastructure regressions but do not prove full mathematical correctness for every algorithm.
- Some educational flows are still best validated with a mix of focused tests and manual Streamlit checks.

## Notes

- Relevant sources: `docs/testing-strategy.md`, `pyproject.toml`, and the current `tests/` tree.
