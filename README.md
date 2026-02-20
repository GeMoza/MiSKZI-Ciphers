# MiSKZI-Ciphers

Educational toolkit of classical ciphers for the MiSKZI course.

The project implements classical cryptographic algorithms strictly according to methodological guidelines
and is designed for semester-long practical work.

---

## Version

Current version: **0.4.2**

---

## Implemented Ciphers (Practice №1)

- Book Cipher (row/column)
- Scytale (parameter r — number of rows)
- Polybius Square (methods 1, 2, 3)
- Magic Square (4×4, table-based)
- Caesar Cipher
- Atbash

All algorithms follow the official methodical instructions.

---

## Project Structure

```
MiSKZI-Ciphers/
├── main.py
├── common/
├── ciphers/
├── data/
│   └── <cipher_name>/
│       ├── variants.json
│       ├── free_text.txt
│       └── (optional key files)
├── tests/
├── pyproject.toml
└── README.md
```

### Directory Overview

- **main.py** — unified CLI entry point
- **common/** — shared utilities and base interfaces
- **ciphers/** — individual cipher implementations
- **data/** — methodical variants and auxiliary files
- **tests/** — automated tests

---

## Installation

Python version required:

```
Python 3.11+
```

Install development dependencies (optional):

```
pip install -e .[dev]
```

---

## Quick Start

List available ciphers:

```
python main.py --list-ciphers
```

Describe a cipher:

```
python main.py --cipher polybius --describe
```

---

## Working with Methodical Variants

Variants are stored in:

```
data/<cipher_name>/variants.json
```

Run a specific variant:

```
python main.py --cipher <cipher_name> --variant <number>
```

Example:

```
python main.py --cipher polybius --variant 5
```

The mode (encrypt/decrypt) is automatically taken from the variant configuration.

---

## Encrypting Custom Text

```
python main.py --cipher <cipher_name> --mode encrypt --text "TEXT" --key ...
```

Example (Caesar):

```
python main.py --cipher caesar --mode encrypt --text "МИРЭА" --key k=3
```

---

## Decrypting

```
python main.py --cipher <cipher_name> --mode decrypt --text "CIPHERTEXT" --key ...
```

---

## Using free_text.txt

```
python main.py --cipher <cipher_name> --mode encrypt --free --key ...
```

---

## Cipher Parameters

### Book Cipher

```
--key key_path=data/book_cipher/key.txt
```

Note:  
If the letter «Э» is absent in the key text, it may be replaced with «Е» during encryption.
This makes the algorithm non-reversible for that letter.

---

### Scytale

```
--key r=4
```

---

### Polybius

```
--key method=1
--key method=2
--key method=3
```

---

### Magic Square

No key required.  
Message length must be exactly 16 characters.

---

### Caesar

```
--key k=6
```

---

### Atbash

No key required.

---

## Roundtrip Verification

Example:

```
python main.py --cipher scytale --mode encrypt --free --key r=4
python main.py --cipher scytale --mode decrypt --text "<result>" --key r=4
```

---

## Running Tests

```
pytest -q
```

---

## Architecture

The project follows a modular architecture:

- Each cipher implements a unified interface:
  - `parse_key()`
  - `encrypt()`
  - `decrypt()`
  - `describe()`
- CLI does not contain cipher-specific logic
- Keys from CLI and variants are normalized through `parse_key()`
- Ciphers are dynamically registered via the central registry

This structure allows adding new ciphers without modifying the CLI logic.

---

## Adding a New Cipher

1. Create a new directory inside `ciphers/`
2. Implement the required cipher interface
3. Add methodical variants inside `data/<cipher_name>/`
4. Add tests in `tests/`

The architecture is designed to scale across multiple practical assignments during the semester.

---

## License

MIT License
