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
from miskzi_ciphers.ui.i18n import (
    description_override,
    get_lang,
    label_cipher,
    label_family,
    label_param,
    label_param_help,
    label_param_value,
    t,
)


st.set_page_config(page_title="MiSKZI Ciphers UI", layout="wide")


def _init_playground_state() -> None:
    st.session_state.setdefault("pg_plaintext", "")
    st.session_state.setdefault("pg_ciphertext", "")
    st.session_state.setdefault("pg_decrypted", "")
    st.session_state.setdefault("pg_key_raw_json", "{}")
    st.session_state.setdefault("pg_key_form_values", {})
    st.session_state.setdefault("pg_key_mode", t("Form"))
    st.session_state.setdefault("pg_feedback", None)
    st.session_state.setdefault("pg_loaded_source_type", None)
    st.session_state.setdefault("pg_loaded_variant_id", None)
    st.session_state.setdefault("pg_loaded_cipher_id", None)


def _init_ui_cipher_state(ciphers: list[str]) -> str:
    if not ciphers:
        raise ValueError("No ciphers available")
    if st.session_state.get("ui_cipher_id") not in ciphers:
        st.session_state["ui_cipher_id"] = ciphers[0]
    return str(st.session_state["ui_cipher_id"])


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


def _ensure_widget_state(key: str, value: Any, *, force: bool = False) -> None:
    current = st.session_state.get(key)
    if key not in st.session_state:
        st.session_state[key] = value
        return

    if force or type(current) is not type(value):
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
        _ensure_widget_state(state_key, coerced, force=True)


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
        help_text = _param_help_text(cipher_id, p)

        fallback_raw = _fallback_raw_value(p)
        key = f"pg_key.{cipher_id}.{name}"
        raw_default = st.session_state.get(key, values.get(name, fallback_raw))
        coerced = _coerce_widget_value(p, raw_default, cipher_id=cipher_id, param_name=name)
        _ensure_widget_state(key, coerced)

        if p_type == "int":
            out[name] = int(st.number_input(label, key=key, step=1, help=help_text))
        elif p_type == "bool":
            out[name] = bool(st.checkbox(label, key=key, help=help_text))
        elif p_type == "enum":
            options = p.get("options", p.get("choices", [])) or []
            if options:
                out[name] = st.selectbox(
                    label,
                    options,
                    key=key,
                    help=help_text,
                    format_func=lambda value, cid=cipher_id, pn=name: label_param_value(cid, pn, value),
                )
            else:
                val = st.text_input(label, key=key, help=help_text)
                if val != "" or required:
                    out[name] = val
        else:
            val = st.text_input(label, key=key, help=help_text)
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




def _pretty_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


def _param_help_text(cipher_id: str, param: dict[str, Any]) -> str | None:
    name = str(param.get("name", "")).strip()
    if not name:
        return None
    raw_help = str(param.get("help", "")).strip()
    fallback_help = raw_help if raw_help else None
    return label_param_help(cipher_id, name, fallback_help)


def _variant_mode_label(mode: str) -> str:
    if mode == "encrypt":
        return t("Encrypt mode")
    if mode == "decrypt":
        return t("Decrypt mode")
    return mode


def _show_description(cipher_id: str) -> None:
    desc = service.get_cipher_description(cipher_id)
    override = description_override(cipher_id)
    if override:
        st.write(override)

    st.subheader(t("Technical description"))
    st.write(f"**{t('Cipher name')}:** {label_cipher(cipher_id)}")
    st.write(f"**{t('Family')}:** {label_family(str(desc.get('family', '')))}")
    st.write(f"**{t('Notes')}:**")
    st.write(desc.get("notes", ""))

    params = desc.get("params", []) or []
    if params:
        prepared = []
        for p in params:
            if not isinstance(p, dict):
                continue
            param_name = str(p.get("name", ""))
            item: dict[str, Any] = {
                t("Parameter"): label_param(cipher_id, param_name),
                t("Raw key"): param_name,
                t("Type"): str(p.get("type", "")),
                t("Required"): t("Yes") if bool(p.get("required", False)) else t("No"),
                t("Default"): p.get("default", ""),
                t("Help"): _param_help_text(cipher_id, p) or "",
                t("Example"): p.get("example", ""),
            }
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
        _ensure_widget_state(f"pg_key.{cipher_id}.{name}", coerced, force=True)


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
    st.session_state["pg_loaded_source_type"] = "variant"
    st.session_state["pg_loaded_variant_id"] = item.get("id") if isinstance(item.get("id"), int) else None
    st.session_state["pg_loaded_cipher_id"] = cipher_id


def _load_key_example_into_playground(cipher_id: str, key_obj: dict[str, Any]) -> None:
    st.session_state["pg_key_form_values"] = dict(key_obj)
    st.session_state["pg_key_raw_json"] = json.dumps(key_obj, ensure_ascii=False, indent=2)
    _sync_key_form_widgets(cipher_id, key_obj)


def _on_load_free_text(cipher_id: str) -> None:
    meta = service.load_meta(cipher_id)
    free_text = str(meta.get("free_text", "")) if isinstance(meta.get("free_text"), str) else ""
    st.session_state["pg_plaintext"] = free_text
    st.session_state["pg_ciphertext"] = ""
    st.session_state["pg_decrypted"] = ""

    raw_key_example = meta.get("raw_key_example", {})
    if isinstance(raw_key_example, dict) and raw_key_example:
        _load_key_example_into_playground(cipher_id, raw_key_example)

    st.session_state["pg_loaded_source_type"] = "free_text"
    st.session_state["pg_loaded_variant_id"] = None
    st.session_state["pg_loaded_cipher_id"] = cipher_id

    message = f"{t('Loaded free_text')}. {t('Read-only: does not modify saved data')}"
    if isinstance(raw_key_example, dict) and raw_key_example:
        message += f" {t('Loaded key example')}."
    _set_feedback("info", message)


def _on_reset_playground() -> None:
    st.session_state["pg_plaintext"] = ""
    st.session_state["pg_ciphertext"] = ""
    st.session_state["pg_decrypted"] = ""
    st.session_state["pg_loaded_source_type"] = None
    st.session_state["pg_loaded_variant_id"] = None
    st.session_state["pg_loaded_cipher_id"] = None
    _set_feedback("info", t("Playground reset"))


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
    _init_ui_cipher_state(ciphers)
    cipher_id = st.selectbox(
        t("Cipher"),
        ciphers,
        key="ui_cipher_id",
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
    st.button(t("Reset playground"), on_click=_on_reset_playground)


def _data_manager() -> None:
    st.header(t("Data Manager"))

    ciphers = service.list_ciphers()
    _init_ui_cipher_state(ciphers)
    cipher_id = st.selectbox(
        t("Cipher"),
        ciphers,
        key="ui_cipher_id",
        format_func=lambda cid: label_cipher(cid),
    )

    cipher_dir = service.data_dir() / cipher_id
    st.write(f"{t('Data directory')}: {service.data_dir()}")
    st.write(f"{t('Cipher directory')}: {cipher_dir}")

    variants_obj = service.load_variants(cipher_id)
    items = variants_obj.get("items", []) if isinstance(variants_obj, dict) else []
    meta = variants_obj.get("meta", {}) if isinstance(variants_obj, dict) else {}
    if not isinstance(meta, dict):
        meta = {}

    meta_free_text_key = f"dm.meta.free_text.{cipher_id}"
    meta_notes_key = f"dm.meta.notes.{cipher_id}"
    meta_key_json_key = f"dm.meta.raw_key_example.{cipher_id}"
    meta_error_key = f"dm.meta.error.{cipher_id}"

    if meta_free_text_key not in st.session_state:
        st.session_state[meta_free_text_key] = str(meta.get("free_text", "")) if isinstance(meta.get("free_text"), str) else ""
    if meta_notes_key not in st.session_state:
        st.session_state[meta_notes_key] = str(meta.get("notes", "")) if isinstance(meta.get("notes"), str) else ""
    if meta_key_json_key not in st.session_state:
        raw_key_example = meta.get("raw_key_example", {})
        if not isinstance(raw_key_example, dict):
            raw_key_example = {}
        st.session_state[meta_key_json_key] = _pretty_json(raw_key_example)

    if meta_error := st.session_state.get(meta_error_key):
        st.error(str(meta_error))
        st.session_state.pop(meta_error_key, None)

    def _build_meta_payload() -> dict[str, Any] | None:
        raw_key_text = str(st.session_state.get(meta_key_json_key, "")).strip()
        if not raw_key_text:
            raw_key_example_obj: dict[str, Any] = {}
        else:
            try:
                parsed = json.loads(raw_key_text)
            except json.JSONDecodeError as e:
                message = f"{t('JSON error')}: {e}"
                st.session_state[meta_error_key] = message
                st.error(message)
                return None
            if not isinstance(parsed, dict):
                message = t("raw key example JSON must be object")
                st.session_state[meta_error_key] = message
                st.error(message)
                return None
            raw_key_example_obj = parsed

        return {
            "free_text": str(st.session_state.get(meta_free_text_key, "")),
            "notes": str(st.session_state.get(meta_notes_key, "")),
            "raw_key_example": raw_key_example_obj,
        }

    st.subheader(t("Meta"))
    st.text_area(t("Free text"), key=meta_free_text_key, height=180)
    st.text_area(t("Notes"), key=meta_notes_key, height=100)
    st.text_area(t("Raw key example"), key=meta_key_json_key, height=160)
    if st.button(t("Save meta"), key=f"dm.save_meta.{cipher_id}"):
        meta_payload = _build_meta_payload()
        if meta_payload is not None:
            payload = {
                "meta": meta_payload,
                "items": [dict(x) for x in items if isinstance(x, dict)],
            }
            errors = service.validate_variants_obj(payload)
            if errors:
                st.error(t("Validation errors"))
                for err in errors:
                    st.error(err)
            else:
                service.save_variants(cipher_id, payload)
                st.success(t("Saved meta"))

    st.subheader(t("Variants"))
    st.dataframe(items)

    options = [f"id={it.get('id')}" for it in items if isinstance(it, dict) and "id" in it]
    select_mode = st.radio(t("Edit variant"), [t("Edit existing"), t("Add new")], horizontal=True, key=f"dm.select_mode.{cipher_id}")

    current: dict[str, Any] = {"id": 1, "mode": "encrypt", "text": "", "key": {}, "expected": ""}

    selected_id_or_new = "new"
    if select_mode == t("Edit existing"):
        if options:
            selected = st.selectbox(t("Select variant"), options, key=f"dm.select_variant.{cipher_id}")
            selected_id = int(selected.split("=")[1])
            selected_id_or_new = str(selected_id)
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

    mode_slug = "edit" if select_mode == t("Edit existing") else "add"
    ctx = f"{cipher_id}.{mode_slug}.{selected_id_or_new}"

    key_id = f"dm.id.{ctx}"
    key_mode = f"dm.mode.{ctx}"
    key_text = f"dm.text.{ctx}"
    key_keyobj = f"dm.key_obj.{ctx}"
    key_keyjson = f"dm.key_json_text.{ctx}"
    key_keymode = f"dm.key_mode.{ctx}"
    key_expected = f"dm.expected.{ctx}"
    key_error = f"dm.error.{ctx}"

    raw_key = current["key"] if isinstance(current.get("key"), dict) else {}

    if key_id not in st.session_state:
        st.session_state[key_id] = int(current["id"])
    if key_mode not in st.session_state:
        st.session_state[key_mode] = str(current["mode"])
    if key_text not in st.session_state:
        st.session_state[key_text] = str(current["text"])
    if key_keyobj not in st.session_state:
        st.session_state[key_keyobj] = json.loads(json.dumps(raw_key, ensure_ascii=False))
    if key_keyjson not in st.session_state:
        st.session_state[key_keyjson] = _pretty_json(raw_key)
    if key_keymode not in st.session_state:
        st.session_state[key_keymode] = t("Form")
    if key_expected not in st.session_state:
        st.session_state[key_expected] = str(current["expected"])

    if msg := st.session_state.get(key_error):
        st.error(str(msg))
        st.session_state.pop(key_error, None)

    def _sync_to_raw_json() -> None:
        key_obj = st.session_state.get(key_keyobj, {})
        if not isinstance(key_obj, dict):
            key_obj = {}
        st.session_state[key_keyjson] = _pretty_json(key_obj)

    def _apply_raw_json_to_form() -> None:
        try:
            parsed = json.loads(str(st.session_state.get(key_keyjson, "")) or "{}")
        except json.JSONDecodeError as e:
            st.session_state[key_error] = f"{t('key JSON error')}: {e}"
            return
        if not isinstance(parsed, dict):
            st.session_state[key_error] = t("key JSON must be object")
            return
        try:
            service.parse_key(cipher_id, parsed)
        except Exception as e:
            st.session_state[key_error] = str(e)
            return
        st.session_state[key_keyobj] = parsed

    vid = st.number_input(t("Identifier"), min_value=1, step=1, key=key_id)
    vmode = st.selectbox(t("Mode"), ["encrypt", "decrypt"], key=key_mode, format_func=_variant_mode_label)
    vtext = st.text_area(t("Text"), key=key_text)
    key_modes = [t("Form"), t("Raw JSON")]
    current_mode = st.session_state.get(key_keymode, t("Form"))
    mode_index = key_modes.index(current_mode) if current_mode in key_modes else 0
    key_input_mode = st.radio(t("Key input"), key_modes, index=mode_index, key=key_keymode, horizontal=True)
    desc = service.get_cipher_description(cipher_id)

    if key_input_mode == t("Raw JSON"):
        st.text_area(t("Key JSON object"), key=key_keyjson)
        st.button(t("Apply JSON to Form"), key=f"dm.apply_raw.{ctx}", on_click=_apply_raw_json_to_form)
    else:
        params = desc.get("params", []) if isinstance(desc, dict) else []
        current_key = st.session_state.get(key_keyobj, {})
        if not isinstance(current_key, dict):
            current_key = {}

        form_raw_key: dict[str, Any] = {}
        for p in params or []:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name", "")).strip()
            if not name:
                continue

            p_type = str(p.get("type", "str"))
            required = bool(p.get("required", False))
            display_name = label_param(cipher_id, name)
            label = f"{display_name} ({p_type})"
            if not required:
                label += f" [{t('Optional')}]"
            help_text = _param_help_text(cipher_id, p)

            fallback_raw = _fallback_raw_value(p)
            raw_default = current_key.get(name, fallback_raw)
            state_key = f"dm.key_form.{ctx}.{name}"
            coerced = _coerce_widget_value(p, raw_default, cipher_id=cipher_id, param_name=name)
            _ensure_widget_state(state_key, coerced)

            if p_type == "int":
                value: Any = int(st.number_input(label, key=state_key, step=1, help=help_text))
            elif p_type == "bool":
                value = bool(st.checkbox(label, key=state_key, help=help_text))
            elif p_type == "enum":
                options = p.get("options", p.get("choices", [])) or []
                if options:
                    value = st.selectbox(label, options, key=state_key, help=help_text, format_func=lambda v, cid=cipher_id, pn=name: label_param_value(cid, pn, v))
                else:
                    value = st.text_input(label, key=state_key, help=help_text)
            else:
                value = st.text_input(label, key=state_key, help=help_text)

            if value != "" or required:
                form_raw_key[name] = _coerce_widget_value(p, value, cipher_id=cipher_id, param_name=name)

        st.session_state[key_keyobj] = dict(form_raw_key)
        st.code(_pretty_json(st.session_state[key_keyobj]), language="json")
        st.button(t("Sync to Raw JSON"), key=f"dm.sync_to_raw.{ctx}", on_click=_sync_to_raw_json)

    vexpected = st.text_area(t("Expected optional"), key=key_expected)

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button(t("Save"), key="dm_save"):
            save_key_obj = st.session_state.get(key_keyobj, {})
            if not isinstance(save_key_obj, dict):
                st.error(t("Cannot save key JSON object"))
                return

            if key_input_mode == t("Raw JSON"):
                try:
                    parsed = json.loads(str(st.session_state.get(key_keyjson, "")) or "{}")
                except json.JSONDecodeError as e:
                    st.error(f"{t('key JSON error')}: {e}")
                    return
                if not isinstance(parsed, dict):
                    st.error(t("key JSON must be object"))
                    return
                try:
                    service.parse_key(cipher_id, parsed)
                except Exception as e:
                    st.error(str(e))
                    return
                st.session_state[key_keyobj] = parsed
                save_key_obj = parsed
            else:
                try:
                    service.parse_key(cipher_id, save_key_obj)
                except Exception as e:
                    st.error(str(e))
                    return

            updated = [dict(x) for x in items if isinstance(x, dict)]
            row: dict[str, Any] = {
                "id": int(vid),
                "mode": vmode,
                "text": vtext,
                "key": save_key_obj,
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

            payload = {"meta": meta, "items": sorted(updated, key=lambda x: int(x.get("id", 0)))}
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
            payload = {"meta": meta, "items": sorted(updated, key=lambda x: int(x.get("id", 0)))}
            errors = service.validate_variants_obj(payload)
            if errors:
                st.error(t("Validation errors"))
                for err in errors:
                    st.error(err)
            else:
                service.save_variants(cipher_id, payload)
                st.success(t("Deleted variant"))
    with c3:
        if st.button(t("Reset form"), key=f"dm_reset.{ctx}"):
            st.session_state.pop(key_id, None)
            st.session_state.pop(key_mode, None)
            st.session_state.pop(key_text, None)
            st.session_state.pop(key_keyobj, None)
            st.session_state.pop(key_keyjson, None)
            st.session_state.pop(key_keymode, None)
            st.session_state.pop(key_expected, None)
            st.session_state.pop(key_error, None)
            form_prefix = f"dm.key_form.{ctx}."
            for state_key in list(st.session_state.keys()):
                if state_key.startswith(form_prefix):
                    st.session_state.pop(state_key, None)
            st.rerun()

    c4, _, _ = st.columns(3)
    with c4:
        if st.button(t("Run variant"), key="dm_run"):
            run_key_obj = st.session_state.get(key_keyobj, {})
            if not isinstance(run_key_obj, dict):
                st.error(t("Cannot run key JSON object"))
            else:
                if key_input_mode == t("Raw JSON"):
                    try:
                        parsed = json.loads(str(st.session_state.get(key_keyjson, "")) or "{}")
                    except json.JSONDecodeError as e:
                        st.error(f"{t('key JSON error')}: {e}")
                        return
                    if not isinstance(parsed, dict):
                        st.error(t("key JSON must be object"))
                        return
                    try:
                        service.parse_key(cipher_id, parsed)
                    except Exception as e:
                        st.error(str(e))
                        return
                    st.session_state[key_keyobj] = parsed
                    run_key_obj = parsed
                else:
                    try:
                        service.parse_key(cipher_id, run_key_obj)
                    except Exception as e:
                        st.error(str(e))
                        return

                try:
                    if vmode == "encrypt":
                        result = service.encrypt(cipher_id, vtext, run_key_obj)
                    else:
                        result = service.decrypt(cipher_id, vtext, run_key_obj)
                    st.write(t("Result"))
                    st.code(result)
                    if vexpected.strip():
                        if result == vexpected:
                            st.success(t("expected match"))
                        else:
                            st.error(t("expected mismatch"))
                except Exception as e:
                    st.error(str(e))


def main() -> None:

    _ = get_lang()
    page = st.sidebar.radio(t("Page"), [t("Playground"), t("Data Manager")])
    if page == t("Playground"):
        _playground()
    else:
        _data_manager()


if __name__ == "__main__":
    main()
