from __future__ import annotations

import json

import streamlit as st

from miskzi_ciphers.app import service
from miskzi_ciphers.ui.app import (
    _loaded_layout_variant_for_cipher,
    _prepare_description_params,
    _raw_key_for_callback,
    _sync_data_manager_key_form_widgets,
)
from miskzi_ciphers.ui.i18n import t


def test_prepare_description_params_serializes_complex_values() -> None:
    desc = service.get_cipher_description("hill")

    prepared = _prepare_description_params("hill", desc.get("params", []))

    matrix_row = next(row for row in prepared if row[t("Raw key")] == "matrix")
    assert matrix_row[t("Example")] == "[[1, 2], [3, 5]]"
    assert all(not isinstance(value, (list, dict, tuple)) for row in prepared for value in row.values())


def test_prepare_description_params_handles_other_cipher_descriptions() -> None:
    for cipher_id in ("ramsey", "rubik_2x2"):
        desc = service.get_cipher_description(cipher_id)
        prepared = _prepare_description_params(cipher_id, desc.get("params", []))

        assert prepared
        assert all(not isinstance(value, (list, dict, tuple)) for row in prepared for value in row.values())


def test_raw_key_for_callback_syncs_playground_form_state_from_raw_json() -> None:
    st.session_state.clear()
    st.session_state["pg_key_mode"] = t("Raw JSON")
    st.session_state["pg_key_raw_json"] = json.dumps({"matrix": [[1, 2], [3, 5]], "pad_char": "А"}, ensure_ascii=False)
    st.session_state["pg_key.hill.matrix"] = ""
    st.session_state["pg_key.hill.pad_char"] = ""

    parsed = _raw_key_for_callback("hill")

    assert parsed == {"matrix": [[1, 2], [3, 5]], "pad_char": "А"}
    assert st.session_state["pg_key_form_values"] == {"matrix": [[1, 2], [3, 5]], "pad_char": "А"}
    assert st.session_state["pg_key.hill.matrix"] == "[[1, 2], [3, 5]]"
    assert st.session_state["pg_key.hill.pad_char"] == "А"


def test_sync_data_manager_key_form_widgets_forces_widget_state_update() -> None:
    st.session_state.clear()
    ctx = "hill.edit.1"
    st.session_state[f"dm.key_form.{ctx}.matrix"] = ""
    st.session_state[f"dm.key_form.{ctx}.pad_char"] = ""

    _sync_data_manager_key_form_widgets("hill", ctx, {"matrix": [[1, 2], [3, 5]], "pad_char": "Б"})

    assert st.session_state[f"dm.key_form.{ctx}.matrix"] == "[[1, 2], [3, 5]]"
    assert st.session_state[f"dm.key_form.{ctx}.pad_char"] == "Б"


def test_loaded_layout_variant_for_cipher_returns_only_matching_layout_item() -> None:
    st.session_state.clear()
    layout_item = {
        "id": 1,
        "input_mode": "layout",
        "layout": {"1_tl": "М"},
        "key": {"moves": []},
    }
    st.session_state["pg_loaded_cipher_id"] = "rubik_2x2"
    st.session_state["pg_loaded_variant_item"] = layout_item

    assert _loaded_layout_variant_for_cipher("rubik_2x2") == layout_item
    assert _loaded_layout_variant_for_cipher("hill") is None

    st.session_state["pg_loaded_variant_item"] = {"id": 2, "input_mode": "text", "text": "ABC"}
    assert _loaded_layout_variant_for_cipher("rubik_2x2") is None
