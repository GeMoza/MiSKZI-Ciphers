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
from miskzi_ciphers.ui.i18n import description_override, get_lang, label_cipher, label_param, t


st.set_page_config(page_title="MiSKZI Ciphers UI", layout="wide")


def _init_playground_state() -> None:
    st.session_state.setdefault("pg_plaintext", "")
    st.session_state.setdefault("pg_ciphertext", "")
    st.session_state.setdefault("pg_decrypted", "")
    st.session_state.setdefault("pg_key_raw_json", "{}")
    st.session_state.setdefault("pg_key_form_values", {})
    st.session_state.setdefault("pg_key_mode", t("Form"))


def _form_default_value(param: dict[str, Any], current: dict[str, Any]) -> Any:
    name = str(param.get("name", ""))
    if name in current:
        return current[name]
    if "default" in param:
        return param["default"]
    if "example" in param:
        return param["example"]
    return ""


def _build_form_key(cipher_id: str, desc: dict[str, Any]) -> dict[str, Any]:
    values = st.session_state.get("pg_key_form_values", {})
    if not isinstance(values, dict):
        values = {}

    out: dict[str, Any] = {}
    for p in desc.get("params", []) or []:
        name = str(p.get("name", "")).strip()
        if not name:
            continue

        p_type = str(p.get("type", "str"))
        required = bool(p.get("required", False))
        display_name = label_param(cipher_id, name)
        label = f"{display_name} ({p_type})"
        if not required:
            label += f" [{t('Optional')}]"

        default = _form_default_value(p, values)
        key = f"pg_form_{name}"

        if p_type == "int":
            val = st.text_input(label, value=str(default) if default != "" else "", key=key)
            if val != "":
                out[name] = val
        elif p_type == "bool":
            bool_default = bool(default) if default != "" else False
            out[name] = st.checkbox(label, value=bool_default, key=key)
        elif p_type == "enum":
            choices = p.get("choices", []) or []
            if choices:
                idx = 0
                if default in choices:
                    idx = choices.index(default)
                out[name] = st.selectbox(label, choices, index=idx, key=key)
            else:
                val = st.text_input(label, value=str(default), key=key)
                if val != "" or required:
                    out[name] = val
        else:
            val = st.text_input(label, value=str(default), key=key)
            if val != "" or required:
                out[name] = val

    st.session_state["pg_key_form_values"] = dict(out)
    return out


def _parse_raw_json(raw_text: str) -> dict[str, Any] | None:
    if not raw_text.strip():
        return {}
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError as e:
        st.error(f"{t('JSON error')}: {e}")
        return None
    if not isinstance(loaded, dict):
        st.error(t("Raw JSON key must be an object"))
        return None
    return loaded


def _show_description(cipher_id: str) -> None:
    desc = service.get_cipher_description(cipher_id)
    override = description_override(cipher_id)
    if override:
        st.write(override)

    st.subheader(t("Technical description"))
    st.write(desc.get("notes", ""))

    params = desc.get("params", []) or []
    if params:
        prepared = []
        for p in params:
            if not isinstance(p, dict):
                continue
            item = dict(p)
            param_name = str(item.get("name", ""))
            item[t("Parameter")] = label_param(cipher_id, param_name)
            prepared.append(item)
        st.table(prepared)
    else:
        st.write(t("No params"))


def _variant_preview(item: dict[str, Any]) -> str:
    text = str(item.get("text", "")).replace("\n", " ")
    if len(text) > 40:
        text = text[:37] + "..."
    return f"id={item.get('id')} | {item.get('mode')} | {text}"


def _load_variant_into_playground(item: dict[str, Any]) -> None:
    key_obj = item.get("key", {})
    if not isinstance(key_obj, dict):
        key_obj = {}

    st.session_state["pg_key_form_values"] = dict(key_obj)
    st.session_state["pg_key_raw_json"] = json.dumps(key_obj, ensure_ascii=False, indent=2)

    mode = item.get("mode")
    text = str(item.get("text", ""))
    if mode == "encrypt":
        st.session_state["pg_plaintext"] = text
        st.session_state["pg_ciphertext"] = ""
        st.session_state["pg_decrypted"] = ""
    elif mode == "decrypt":
        st.session_state["pg_ciphertext"] = text
        st.session_state["pg_plaintext"] = ""
        st.session_state["pg_decrypted"] = ""

    st.info(f"{t('Loaded variant')}. {t('Read-only: does not modify saved data')}")


def _playground() -> None:
    _init_playground_state()
    st.header(t("Playground"))

    ciphers = service.list_ciphers()
    cipher_id = st.selectbox(
        t("Cipher"),
        ciphers,
        key="pg_cipher",
        format_func=lambda cid: label_cipher(cid),
    )
    desc = service.get_cipher_description(cipher_id)

    with st.expander(t("Description")):
        _show_description(cipher_id)

    key_modes = [t("Form"), t("Raw JSON")]
    default_mode = st.session_state.get("pg_key_mode", t("Form"))
    mode_index = key_modes.index(default_mode) if default_mode in key_modes else 0
    key_mode = st.radio(t("Key input mode"), key_modes, index=mode_index, horizontal=True)
    st.session_state["pg_key_mode"] = key_mode

    raw_key: dict[str, Any] = {}
    if key_mode == t("Form"):
        raw_key = _build_form_key(cipher_id, desc)
    else:
        raw_text = st.text_area(t("Raw key JSON"), key="pg_key_raw_json")
        parsed = _parse_raw_json(raw_text)
        raw_key = {} if parsed is None else parsed
        if parsed is not None:
            st.session_state["pg_key_form_values"] = dict(parsed)

    if st.button(t("Parse key"), key="pg_parse"):
        try:
            parsed_key = service.parse_key(cipher_id, raw_key)
            st.success(t("Key parsed"))
            st.json(parsed_key)
        except Exception as e:
            st.error(str(e))

    st.subheader(t("Load input"))
    source_options = [t("None"), t("Variant"), t("Free text")]
    source = st.selectbox(t("Source"), source_options, key="pg_source")

    if source == t("Variant"):
        variants_obj = service.load_variants(cipher_id)
        items = variants_obj.get("items", []) if isinstance(variants_obj, dict) else []
        valid_items = [x for x in items if isinstance(x, dict)]
        if valid_items:
            options = [_variant_preview(v) for v in valid_items]
            selected = st.selectbox(t("Select variant"), options, key="pg_variant_select")
            if st.button(t("Load variant"), key="pg_load_variant"):
                idx = options.index(selected)
                _load_variant_into_playground(valid_items[idx])
        else:
            st.info(t("No variants"))
    elif source == t("Free text"):
        if st.button(t("Load free_text"), key="pg_load_free_text"):
            free_text = service.load_free_text(cipher_id)
            st.session_state["pg_plaintext"] = free_text
            st.session_state["pg_ciphertext"] = ""
            st.session_state["pg_decrypted"] = ""
            st.info(f"{t('Loaded free_text')}. {t('Read-only: does not modify saved data')}")

    col1, col2, col3 = st.columns(3)
    with col1:
        plaintext = st.text_area(t("Plaintext"), key="pg_plaintext")
    with col2:
        ciphertext = st.text_area(t("Ciphertext"), key="pg_ciphertext")
    with col3:
        decrypted = st.text_area(t("Decrypted"), key="pg_decrypted")

    btn1, btn2, btn3 = st.columns(3)
    with btn1:
        if st.button(t("Encrypt")):
            try:
                out = service.encrypt(cipher_id, plaintext, raw_key)
                st.session_state["pg_ciphertext"] = out
                st.success(t("Encrypted"))
            except Exception as e:
                st.error(str(e))
    with btn2:
        if st.button(t("Decrypt")):
            try:
                out = service.decrypt(cipher_id, ciphertext, raw_key)
                st.session_state["pg_decrypted"] = out
                st.success(t("Decrypted action"))
            except Exception as e:
                st.error(str(e))
    with btn3:
        if st.button(t("Roundtrip")):
            try:
                enc = service.encrypt(cipher_id, plaintext, raw_key)
                dec = service.decrypt(cipher_id, enc, raw_key)
                st.session_state["pg_ciphertext"] = enc
                st.session_state["pg_decrypted"] = dec
                if dec == plaintext:
                    st.success(f"{t('Roundtrip equals')}: True")
                else:
                    st.error(f"{t('Roundtrip equals')}: False\nExpected: {plaintext}\nGot: {dec}")
            except Exception as e:
                st.error(str(e))


def _data_manager() -> None:
    st.header(t("Data Manager"))

    ciphers = service.list_ciphers()
    cipher_id = st.selectbox(
        t("Cipher"),
        ciphers,
        key="dm_cipher",
        format_func=lambda cid: label_cipher(cid),
    )

    cipher_dir = service.data_dir() / cipher_id
    st.write(f"data_dir: {service.data_dir()}")
    st.write(f"cipher_dir: {cipher_dir}")

    st.subheader(t("Variants"))
    variants_obj = service.load_variants(cipher_id)
    items = variants_obj.get("items", []) if isinstance(variants_obj, dict) else []

    st.dataframe(items)

    options = [f"id={it.get('id')}" for it in items if isinstance(it, dict) and "id" in it]
    select_mode = st.radio(t("Edit variant"), [t("Edit existing"), t("Add new")], horizontal=True)

    current: dict[str, Any] = {"id": 1, "mode": "encrypt", "text": "", "key": {}, "expected": ""}

    if select_mode == t("Edit existing"):
        if options:
            selected = st.selectbox(t("Select variant"), options)
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
            st.write(t("No variants"))
    else:
        used_ids = [int(x.get("id", 0)) for x in items if isinstance(x, dict) and isinstance(x.get("id"), int)]
        next_id = (max(used_ids) + 1) if used_ids else 1
        current["id"] = next_id

    vid = st.number_input("id", min_value=1, value=int(current["id"]), step=1)
    vmode = st.selectbox("mode", ["encrypt", "decrypt"], index=0 if current["mode"] == "encrypt" else 1)
    vtext = st.text_area("text", value=current["text"], key="dm_vtext")
    vkey_raw = st.text_area(t("Key JSON object"), value=json.dumps(current["key"], ensure_ascii=False, indent=2))
    vexpected = st.text_area(t("Expected optional"), value=current["expected"], key="dm_vexpected")

    parsed_key: dict[str, Any] | None = None
    try:
        parsed_key_any = json.loads(vkey_raw) if vkey_raw.strip() else {}
        if not isinstance(parsed_key_any, dict):
            st.error(t("key JSON must be object"))
        else:
            parsed_key = parsed_key_any
    except json.JSONDecodeError as e:
        st.error(f"{t('key JSON error')}: {e}")

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button(t("Save"), key="dm_save"):
            if parsed_key is None:
                st.error(t("Cannot save key JSON object"))
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
                    st.error(t("Validation errors"))
                    for err in errors:
                        st.error(err)
                else:
                    service.save_variants(cipher_id, payload)
                    st.success(t("Saved variants"))
    with c2:
        if st.button(t("Delete"), key="dm_delete"):
            updated = [dict(x) for x in items if isinstance(x, dict) and x.get("id") != int(vid)]
            payload = {"items": sorted(updated, key=lambda x: int(x.get("id", 0)))}
            errors = service.validate_variants_obj(payload)
            if errors:
                st.error(t("Validation errors"))
                for err in errors:
                    st.error(err)
            else:
                service.save_variants(cipher_id, payload)
                st.success(t("Deleted variant"))
    with c3:
        if st.button(t("Run variant"), key="dm_run"):
            if parsed_key is None:
                st.error(t("Cannot run key JSON object"))
            else:
                try:
                    if vmode == "encrypt":
                        result = service.encrypt(cipher_id, vtext, parsed_key)
                    else:
                        result = service.decrypt(cipher_id, vtext, parsed_key)
                    st.write(t("Result"))
                    st.code(result)
                    if vexpected.strip():
                        if result == vexpected:
                            st.success(t("expected match"))
                        else:
                            st.error(t("expected mismatch"))
                except Exception as e:
                    st.error(str(e))

    st.subheader(t("Free text"))
    ft = st.text_area(t("free_text file"), value=service.load_free_text(cipher_id), height=180)
    if st.button(t("Save free_text")):
        service.save_free_text(cipher_id, ft)
        st.success(t("Saved free_text"))


def main() -> None:
    _ = get_lang()
    page = st.sidebar.radio(t("Page"), [t("Playground"), t("Data Manager")])
    if page == t("Playground"):
        _playground()
    else:
        _data_manager()


if __name__ == "__main__":
    main()
