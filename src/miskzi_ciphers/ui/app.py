from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import streamlit as st

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from miskzi_ciphers.app import service


st.set_page_config(page_title="MiSKZI Ciphers UI", layout="wide")


def _build_form_key(desc: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for p in desc.get("params", []) or []:
        name = str(p.get("name", "")).strip()
        if not name:
            continue
        p_type = str(p.get("type", "str"))
        required = bool(p.get("required", False))
        label = f"{name} ({p_type})"
        if not required:
            label += " [optional]"

        default = p.get("default", p.get("example", ""))

        if p_type == "int":
            val = st.text_input(label, value=str(default) if default != "" else "", key=f"form_{name}")
            if val != "":
                out[name] = val
        elif p_type == "bool":
            bool_default = bool(default) if default != "" else False
            out[name] = st.checkbox(label, value=bool_default, key=f"form_{name}")
        elif p_type == "enum":
            choices = p.get("choices", []) or []
            if choices:
                idx = 0
                if default in choices:
                    idx = choices.index(default)
                out[name] = st.selectbox(label, choices, index=idx, key=f"form_{name}")
            else:
                out[name] = st.text_input(label, value=str(default), key=f"form_{name}")
        else:
            val = st.text_input(label, value=str(default), key=f"form_{name}")
            if val != "" or required:
                out[name] = val
    return out


def _parse_raw_json(raw_text: str) -> dict[str, Any] | None:
    if not raw_text.strip():
        return {}
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError as e:
        st.error(f"JSON error: {e}")
        return None
    if not isinstance(loaded, dict):
        st.error("Raw JSON key must be an object")
        return None
    return loaded


def _show_description(cipher_id: str) -> None:
    desc = service.get_cipher_description(cipher_id)
    st.write(desc.get("notes", ""))
    params = desc.get("params", []) or []
    if params:
        st.table(params)
    else:
        st.write("No params")


def _playground() -> None:
    st.header("Playground")

    ciphers = service.list_ciphers()
    cipher_id = st.selectbox("Cipher", ciphers, key="pg_cipher")
    desc = service.get_cipher_description(cipher_id)

    with st.expander("Description"):
        _show_description(cipher_id)

    key_mode = st.radio("Key input mode", ["Form", "Raw JSON"], horizontal=True)

    if key_mode == "Form":
        raw_key = _build_form_key(desc)
    else:
        raw_text = st.text_area("Raw key JSON", value="{}", key="pg_raw_json")
        parsed = _parse_raw_json(raw_text)
        raw_key = {} if parsed is None else parsed

    if st.button("Parse key", key="pg_parse"):
        try:
            parsed_key = service.parse_key(cipher_id, raw_key)
            st.success("Key parsed")
            st.json(parsed_key)
        except Exception as e:
            st.error(str(e))

    col1, col2, col3 = st.columns(3)
    with col1:
        plaintext = st.text_area("Plaintext", key="pg_plaintext")
    with col2:
        ciphertext = st.text_area("Ciphertext", key="pg_ciphertext")
    with col3:
        decrypted = st.text_area("Decrypted", key="pg_decrypted")

    btn1, btn2, btn3 = st.columns(3)
    with btn1:
        if st.button("Encrypt"):
            try:
                out = service.encrypt(cipher_id, plaintext, raw_key)
                st.session_state["pg_ciphertext"] = out
                st.success("Encrypted")
            except Exception as e:
                st.error(str(e))
    with btn2:
        if st.button("Decrypt"):
            try:
                out = service.decrypt(cipher_id, ciphertext, raw_key)
                st.session_state["pg_decrypted"] = out
                st.success("Decrypted")
            except Exception as e:
                st.error(str(e))
    with btn3:
        if st.button("Roundtrip"):
            try:
                enc = service.encrypt(cipher_id, plaintext, raw_key)
                dec = service.decrypt(cipher_id, enc, raw_key)
                st.session_state["pg_ciphertext"] = enc
                st.session_state["pg_decrypted"] = dec
                if dec == plaintext:
                    st.success("Roundtrip equals: True")
                else:
                    st.error(f"Roundtrip equals: False\nExpected: {plaintext}\nGot: {dec}")
            except Exception as e:
                st.error(str(e))


def _data_manager() -> None:
    st.header("Data Manager")

    ciphers = service.list_ciphers()
    cipher_id = st.selectbox("Cipher", ciphers, key="dm_cipher")

    cipher_dir = service.data_dir() / cipher_id
    st.write(f"data_dir: {service.data_dir()}")
    st.write(f"cipher_dir: {cipher_dir}")

    st.subheader("Variants")
    variants_obj = service.load_variants(cipher_id)
    items = variants_obj.get("items", []) if isinstance(variants_obj, dict) else []

    st.dataframe(items)

    options = [f"id={it.get('id')}" for it in items if isinstance(it, dict) and "id" in it]
    select_mode = st.radio("Variant action", ["Edit existing", "Add new"], horizontal=True)

    current: dict[str, Any] = {"id": 1, "mode": "encrypt", "text": "", "key": {}, "expected": ""}
    selected_id: int | None = None

    if select_mode == "Edit existing":
        if options:
            selected = st.selectbox("Variant", options)
            selected_id = int(selected.split("=")[1])
            found = next((x for x in items if isinstance(x, dict) and x.get("id") == selected_id), None)
            if found:
                current = {
                    "id": int(found.get("id", 1)),
                    "mode": str(found.get("mode", "encrypt")),
                    "text": str(found.get("text", "")),
                    "key": dict(found.get("key", {})),
                    "expected": "" if "expected" not in found else str(found.get("expected", "")),
                }
        else:
            st.write("No variants yet")
    else:
        used_ids = [int(x.get("id", 0)) for x in items if isinstance(x, dict) and isinstance(x.get("id"), int)]
        next_id = (max(used_ids) + 1) if used_ids else 1
        current["id"] = next_id

    vid = st.number_input("id", min_value=1, value=int(current["id"]), step=1)
    vmode = st.selectbox("mode", ["encrypt", "decrypt"], index=0 if current["mode"] == "encrypt" else 1)
    vtext = st.text_area("text", value=current["text"], key="dm_vtext")
    vkey_raw = st.text_area("key (JSON object)", value=json.dumps(current["key"], ensure_ascii=False, indent=2))
    vexpected = st.text_area("expected (optional)", value=current["expected"], key="dm_vexpected")

    parsed_key: dict[str, Any] | None = None
    try:
        parsed_key_any = json.loads(vkey_raw) if vkey_raw.strip() else {}
        if not isinstance(parsed_key_any, dict):
            st.error("key JSON must be object")
        else:
            parsed_key = parsed_key_any
    except json.JSONDecodeError as e:
        st.error(f"key JSON error: {e}")

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Save", key="dm_save"):
            if parsed_key is None:
                st.error("Cannot save: key must be valid JSON object")
            else:
                updated = [dict(x) for x in items if isinstance(x, dict)]
                row: dict[str, Any] = {
                    "id": int(vid),
                    "mode": vmode,
                    "text": vtext,
                    "key": parsed_key,
                }
                if vexpected.strip():
                    row["expected"] = vexpected

                replaced = False
                for idx, it in enumerate(updated):
                    if it.get("id") == int(vid):
                        updated[idx] = row
                        replaced = True
                        break
                if not replaced:
                    updated.append(row)

                payload = {"items": sorted(updated, key=lambda x: int(x.get("id", 0)))}
                errors = service.validate_variants_obj(payload)
                if errors:
                    for err in errors:
                        st.error(err)
                else:
                    service.save_variants(cipher_id, payload)
                    st.success("Saved variants.json")
    with c2:
        if st.button("Delete", key="dm_delete"):
            updated = [dict(x) for x in items if isinstance(x, dict) and x.get("id") != int(vid)]
            payload = {"items": sorted(updated, key=lambda x: int(x.get("id", 0)))}
            errors = service.validate_variants_obj(payload)
            if errors:
                for err in errors:
                    st.error(err)
            else:
                service.save_variants(cipher_id, payload)
                st.success("Deleted variant")
    with c3:
        if st.button("Run variant", key="dm_run"):
            if parsed_key is None:
                st.error("Cannot run: key must be valid JSON object")
            else:
                try:
                    if vmode == "encrypt":
                        result = service.encrypt(cipher_id, vtext, parsed_key)
                    else:
                        result = service.decrypt(cipher_id, vtext, parsed_key)
                    st.write("Result:")
                    st.code(result)
                    if vexpected.strip():
                        if result == vexpected:
                            st.success("expected match")
                        else:
                            st.error("expected mismatch")
                except Exception as e:
                    st.error(str(e))

    st.subheader("Free text")
    ft = st.text_area("free_text.txt", value=service.load_free_text(cipher_id), height=180)
    if st.button("Save free_text"):
        service.save_free_text(cipher_id, ft)
        st.success("Saved free_text.txt")


def main() -> None:
    page = st.sidebar.radio("Page", ["Playground", "Data Manager"])
    if page == "Playground":
        _playground()
    else:
        _data_manager()


if __name__ == "__main__":
    main()
