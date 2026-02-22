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
    st.session_state.setdefault("pg_feedback", None)


def _fallback_raw_value(param: dict[str, Any]) -> Any:
    if "default" in param:
        return param["default"]
    if "example" in param:
        return param["example"]

    p_type = str(param.get("type", "str"))
    options = param.get("options", param.get("choices", [])) or []
    if p_type == "int":
        return 0
    if p_type == "bool":
        return False
    if p_type == "enum" and options:
        return options[0]
    return ""


def _coerce_widget_value(param: dict[str, Any], raw_value: Any, *, cipher_id: str, param_name: str) -> Any:
    _ = cipher_id
    _ = param_name

    p_type = str(param.get("type", "str"))
    if p_type == "int":
        fallback_raw = param.get("default", 0)
        try:
            fallback = int(fallback_raw)
        except (TypeError, ValueError):
            fallback = 0
        if raw_value in (None, ""):
            return fallback
        try:
            return int(raw_value)
        except (TypeError, ValueError):
            return fallback

    if p_type == "bool":
        if raw_value is None:
            return False
        return bool(raw_value)

    if p_type == "enum":
        options = param.get("options", param.get("choices", [])) or []
        if not isinstance(options, (list, tuple)):
            options = []
        if not options:
            return "" if raw_value is None else str(raw_value)
        if raw_value in options:
            return raw_value
        default = param.get("default")
        if default in options:
            return default
        return options[0]

    if raw_value is None:
        return ""
    return str(raw_value)


def _ensure_widget_state(key: str, value: Any) -> None:
    current = st.session_state.get(key)
    if key not in st.session_state or current != value or type(current) is not type(value):
        st.session_state[key] = value


def _sanitize_form_widget_state(cipher_id: str, desc: dict[str, Any]) -> None:
    params = desc.get("params", []) if isinstance(desc, dict) else []
    by_name: dict[str, dict[str, Any]] = {}
    for p in params or []:
        if isinstance(p, dict):
            name = str(p.get("name", "")).strip()
            if name:
                by_name[name] = p

    prefix = f"pg_key.{cipher_id}."
    for state_key in list(st.session_state.keys()):
        if not state_key.startswith(prefix):
            continue
        param_name = state_key[len(prefix) :]
        param = by_name.get(param_name)
        if not param:
            continue
        coerced = _coerce_widget_value(param, st.session_state.get(state_key), cipher_id=cipher_id, param_name=param_name)
        _ensure_widget_state(state_key, coerced)


def _build_form_key(cipher_id: str, desc: dict[str, Any]) -> dict[str, Any]:
    values = st.session_state.get("pg_key_form_values", {})
    if not isinstance(values, dict):
        values = {}

    _sanitize_form_widget_state(cipher_id, desc)

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

        fallback_raw = _fallback_raw_value(p)
        raw_default = values.get(name, fallback_raw)
        key = f"pg_key.{cipher_id}.{name}"
        coerced = _coerce_widget_value(p, raw_default, cipher_id=cipher_id, param_name=name)
        _ensure_widget_state(key, coerced)

        if p_type == "int":
            out[name] = int(st.number_input(label, key=key, step=1))
        elif p_type == "bool":
            out[name] = bool(st.checkbox(label, key=key))
        elif p_type == "enum":
            options = p.get("options", p.get("choices", [])) or []
            if options:
                out[name] = st.selectbox(label, options, key=key)
            else:
                val = st.text_input(label, key=key)
                if val != "" or required:
                    out[name] = val
        else:
            val = st.text_input(label, key=key)
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

    st.session_state["pg_feedback"] = (
        "info",
        f"{t('Loaded variant')}. {t('Read-only: does not modify saved data')}",
    )


def _sync_key_form_widgets(cipher_id: str, key_obj: dict[str, Any]) -> None:
    desc = service.get_cipher_description(cipher_id)
    params = desc.get("params", []) if isinstance(desc, dict) else []
    for p in params or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name", "")).strip()
        if not name:
            continue
        fallback_raw = _fallback_raw_value(p)
        raw_value = key_obj.get(name, fallback_raw)
        coerced = _coerce_widget_value(p, raw_value, cipher_id=cipher_id, param_name=name)
        _ensure_widget_state(f"pg_key.{cipher_id}.{name}", coerced)


def _set_feedback(level: str, message: str) -> None:
    st.session_state["pg_feedback"] = (level, message)


def _show_feedback() -> None:
    feedback = st.session_state.get("pg_feedback")
    if not feedback:
        return
    level, message = feedback
    if level == "success":
        st.success(message)
    elif level == "error":
        st.error(message)
    else:
        st.info(message)


def _raw_key_for_callback() -> dict[str, Any] | None:
    if st.session_state.get("pg_key_mode", t("Form")) == t("Raw JSON"):
        raw_text = str(st.session_state.get("pg_key_raw_json", "{}"))
        parsed = _parse_raw_json(raw_text)
        if parsed is None:
            return None
        st.session_state["pg_key_form_values"] = dict(parsed)
        return parsed

    values = st.session_state.get("pg_key_form_values", {})
    if isinstance(values, dict):
        return dict(values)
    return {}


def _on_load_variant(cipher_id: str, items: list[dict[str, Any]]) -> None:
    selected = str(st.session_state.get("pg_variant_select", ""))
    options = [_variant_preview(v) for v in items]
    if selected not in options:
        _set_feedback("error", t("No variants"))
        return
    idx = options.index(selected)
    item = items[idx]
    _load_variant_into_playground(item)
    key_obj = item.get("key", {})
    if not isinstance(key_obj, dict):
        key_obj = {}
    st.session_state["pg_key_raw_json"] = json.dumps(key_obj, ensure_ascii=False, indent=2)
    _sync_key_form_widgets(cipher_id, key_obj)


def _on_load_free_text(cipher_id: str) -> None:
    free_text = service.load_free_text(cipher_id)
    st.session_state["pg_plaintext"] = free_text
    st.session_state["pg_ciphertext"] = ""
    st.session_state["pg_decrypted"] = ""
    _set_feedback("info", f"{t('Loaded free_text')}. {t('Read-only: does not modify saved data')}")


def _on_encrypt(cipher_id: str) -> None:
    raw_key = _raw_key_for_callback()
    if raw_key is None:
        return
    try:
        out = service.encrypt(cipher_id, str(st.session_state.get("pg_plaintext", "")), raw_key)
        st.session_state["pg_ciphertext"] = out
        _set_feedback("success", t("Encrypted"))
    except Exception as e:
        _set_feedback("error", str(e))


def _on_decrypt(cipher_id: str) -> None:
    raw_key = _raw_key_for_callback()
    if raw_key is None:
        return
    try:
        out = service.decrypt(cipher_id, str(st.session_state.get("pg_ciphertext", "")), raw_key)
        st.session_state["pg_decrypted"] = out
        _set_feedback("success", t("Decrypted action"))
    except Exception as e:
        _set_feedback("error", str(e))


def _on_roundtrip(cipher_id: str) -> None:
    raw_key = _raw_key_for_callback()
    if raw_key is None:
        return
    plaintext = str(st.session_state.get("pg_plaintext", ""))
    try:
        enc = service.encrypt(cipher_id, plaintext, raw_key)
        dec = service.decrypt(cipher_id, enc, raw_key)
        st.session_state["pg_ciphertext"] = enc
        st.session_state["pg_decrypted"] = dec
        if dec == plaintext:
            _set_feedback("success", f"{t('Roundtrip equals')}: True")
        else:
            _set_feedback("error", f"{t('Roundtrip equals')}: False\nExpected: {plaintext}\nGot: {dec}")
    except Exception as e:
        _set_feedback("error", str(e))


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

    if key_mode == t("Form"):
        _build_form_key(cipher_id, desc)
    else:
        st.text_area(t("Raw key JSON"), key="pg_key_raw_json")

    if st.button(t("Parse key"), key="pg_parse"):
        raw_key = _raw_key_for_callback()
        if raw_key is None:
            return
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
            st.selectbox(t("Select variant"), options, key="pg_variant_select")
            st.button(t("Load variant"), key="pg_load_variant", on_click=_on_load_variant, args=(cipher_id, valid_items))
        else:
            st.info(t("No variants"))
    elif source == t("Free text"):
        st.button(t("Load free_text"), key="pg_load_free_text", on_click=_on_load_free_text, args=(cipher_id,))

    col1, col2, col3 = st.columns(3)
    with col1:
        st.text_area(t("Plaintext"), key="pg_plaintext")
    with col2:
        st.text_area(t("Ciphertext"), key="pg_ciphertext")
    with col3:
        st.text_area(t("Decrypted"), key="pg_decrypted")

    _show_feedback()

    btn1, btn2, btn3 = st.columns(3)
    with btn1:
        st.button(t("Encrypt"), on_click=_on_encrypt, args=(cipher_id,))
    with btn2:
        st.button(t("Decrypt"), on_click=_on_decrypt, args=(cipher_id,))
    with btn3:
        st.button(t("Roundtrip"), on_click=_on_roundtrip, args=(cipher_id,))


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
