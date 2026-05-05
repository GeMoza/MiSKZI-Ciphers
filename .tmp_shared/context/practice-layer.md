# Practice Layer

## Invariants

- Practice-specific logic is separated from the base cipher contract.
- The project should not extend the core cipher protocol just to support PR9 or PR10.
- Shared practice infrastructure belongs in `src/miskzi_ciphers/practice/common/`.
- Algorithm-specific educational flows remain split by practice package.

## Current State

- `practice_09` is implemented as a dedicated service over reusable models, normalization, export, histogram, and trace helpers.
- `practice_10` currently exposes only the `playfair` practice scenario in `practice_10/service.py`.
- Existing practice common modules include `models.py`, `export.py`, `histogram.py`, `normalization.py`, and `cipher_adapter.py`.

## API / Interfaces

- `run_practice_09_algorithm(algorithm, operation, text, params)` supports `caesar`, `vigenere`, `gronsfeld`, `invert_255`, and `pair_swap`.
- `run_practice_10_algorithm(algorithm, operation, text, params)` currently supports only `playfair`.
- Practice services return `PracticeResult` objects with steps, tables, notes, and optional histograms.

## Decisions

- PR9 uses educational trace scenarios rather than direct reuse of the normal cipher runtime for every case.
- PR10 MVP-3 is scoped to a Playfair-based educational scenario with configurable alphabet mode.
- Exact compatibility with legacy external executables is not the goal; transparent, reproducible educational behavior is preferred.

## Known Gaps

- PR10 requirements mention both Playfair and Wheatstone, but current code supports only Playfair in the practice service.
- Specialized UI tabs for PR9 and PR10 are described in planning docs but are not part of the main Streamlit app yet.
- Requirements docs still treat parts of PR9/PR10 behavior as needing further formalization.

## Notes

- Relevant sources: `docs/practice/practice-09-requirements.md`, `docs/practice/practice-10-requirements.md`, `docs/practice/practice-implementation-plan.md`, `src/miskzi_ciphers/practice/practice_09/service.py`, `src/miskzi_ciphers/practice/practice_10/service.py`.
