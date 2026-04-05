"""Tests for formatter output helpers (pytest)."""

from __future__ import annotations

import json

import pytest

from formatter import (
    colorize,
    format_table,
    render_report,
    render_report_text,
    serialize_primary_output,
)


def test_serialize_primary_output_text_dict_is_indented_json() -> None:
    out = serialize_primary_output({"a": 1}, "text")
    assert "\n" in out
    assert json.loads(out) == {"a": 1}


def test_serialize_primary_output_raw_dict_is_compact_json() -> None:
    out = serialize_primary_output({"a": 1, "b": [2, 3]}, "raw")
    assert "\n" not in out
    assert json.loads(out) == {"a": 1, "b": [2, 3]}


def test_serialize_primary_output_raw_string_is_plain_str() -> None:
    assert serialize_primary_output("hello", "raw") == "hello"


def test_serialize_primary_output_json_encodes_string_as_json() -> None:
    assert serialize_primary_output("hello", "json") == '"hello"'


def test_format_table_headers_and_rows() -> None:
    table = format_table(["A", "B"], [["1", "2"], ["33", "4"]])
    assert "A" in table and "B" in table
    assert "33" in table
    lines = table.splitlines()
    assert len(lines) >= 3


def test_render_report_text_contains_title_and_summary() -> None:
    result = {
        "title": "Test Report",
        "metadata": {"source": "unit"},
        "stats": {"n": 1},
        "findings": [],
        "warnings": [],
        "errors": [],
        "summary": "Done.",
    }
    text = render_report_text(result, color_enabled=False)
    assert "Test Report" in text
    assert "Done." in text
    assert "source: unit" in text


def test_render_report_json_roundtrip() -> None:
    result = {"title": "T", "output": "x", "analyses": []}
    dumped = render_report(result, report_format="json", color_enabled=False)
    assert json.loads(dumped) == result


def test_colorize_disabled_returns_plain_text() -> None:
    assert colorize("hello", "red", enabled=False) == "hello"


def test_colorize_unknown_color_returns_plain() -> None:
    assert colorize("x", "not_a_color", enabled=True) == "x"
