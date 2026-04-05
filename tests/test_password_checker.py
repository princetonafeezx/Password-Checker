"""Unit tests for password scoring rules and analyze_password."""

from __future__ import annotations

import pytest

from errors import ParseError, ValidationError
from password_checker import (
    analyze_password,
    calculate_entropy,
    character_pool_size,
    check_dictionary,
    check_diversity,
    check_keyboard_patterns,
    check_length,
    check_repeats,
    check_sequences,
    detect_keyboard_patterns,
    detect_sequences,
    grade_from_score,
    mask_password,
    normalized_password,
    run,
    top_feedback,
)


def test_mask_password_respects_show_and_short() -> None:
    assert mask_password("secret", True) == "secret"
    assert mask_password("secret", False) == "s****t"
    assert mask_password("ab", False) == "**"
    assert mask_password("", False) == "<empty>"


def test_normalized_password_leet() -> None:
    assert normalized_password("P@ssw0rd") == "password"


def test_check_length_pass_fail_and_cap() -> None:
    short = check_length("abc", min_length=8)
    assert short["passed"] is False
    assert short["points"] < 20

    ok = check_length("abcdefgh", min_length=8)
    assert ok["passed"] is True

    long_pwd = check_length("a" * 20, min_length=8)
    assert long_pwd["points"] == 20


def test_check_diversity_classes_and_pass_threshold() -> None:
    only_lower = check_diversity("abcdef")
    assert only_lower["passed"] is False
    assert only_lower["points"] == 5

    three_classes = check_diversity("Abc1")
    assert three_classes["passed"] is True
    assert three_classes["points"] == 15


def test_check_dictionary_exact_and_leet() -> None:
    hit = check_dictionary("password")
    assert hit["passed"] is False
    assert hit["points"] == 0

    leet = check_dictionary("p@ssw0rd")
    assert leet["passed"] is False

    clean = check_dictionary("xK9#mQ2$vL5nR8wP1z")
    assert clean["passed"] is True
    assert clean["points"] == 20


def test_detect_and_check_sequences() -> None:
    assert "abc" in detect_sequences("xxabcyy")
    assert detect_sequences("aaa") == []
    seq_rule = check_sequences("abc")
    assert seq_rule["passed"] is False
    assert seq_rule["points"] == 0
    ok = check_sequences("a9z")
    assert ok["passed"] is True


def test_check_repeats() -> None:
    bad = check_repeats("xaaab")
    assert bad["passed"] is False
    good = check_repeats("aabbc")
    assert good["passed"] is True


def test_keyboard_patterns() -> None:
    assert detect_keyboard_patterns("xxqwertyy")
    kb = check_keyboard_patterns("myqwerty1")
    assert kb["passed"] is False


def test_character_pool_size_and_entropy_shape() -> None:
    assert character_pool_size("abc") == 26
    assert character_pool_size("ABC") == 26
    mixed = character_pool_size("Aa1!")
    assert mixed >= 26 + 26 + 10

    ent = calculate_entropy("a" * 40)
    assert ent["name"] == "entropy"
    assert "entropy_bits" in ent
    assert ent["entropy_bits"] is not None
    assert ent["max_points"] == 15


def test_grade_from_score_bands() -> None:
    assert grade_from_score(90) == "Fortress"
    assert grade_from_score(75) == "Strong"
    assert grade_from_score(55) == "Fair"
    assert grade_from_score(35) == "Weak"
    assert grade_from_score(10) == "Terrible"


def test_top_feedback_orders_by_deficit() -> None:
    rules = [
        {"name": "a", "passed": False, "max_points": 20, "points": 0, "feedback": "fix a"},
        {"name": "b", "passed": False, "max_points": 5, "points": 0, "feedback": "fix b"},
        {"name": "c", "passed": True, "max_points": 10, "points": 10, "feedback": "ok"},
    ]
    tips = top_feedback(rules)
    assert tips[0] == "fix a"


def test_analyze_password_skips_dictionary_and_entropy_flags() -> None:
    weak_common = analyze_password("password", {})
    dict_rule = next(r for r in weak_common["rules"] if r["name"] == "dictionary")
    assert dict_rule["passed"] is False

    skipped = analyze_password(
        "password",
        {"no_dictionary": True, "no_entropy": True},
    )
    d = next(r for r in skipped["rules"] if r["name"] == "dictionary")
    e = next(r for r in skipped["rules"] if r["name"] == "entropy")
    assert "skipped" in d["details"].lower()
    assert "skipped" in e["details"].lower()


def test_run_single_vs_batch_and_empty_file() -> None:
    one = run("", {"single_password": "xK9#mQ2$vL5nR8wP1zT7jH4sD6fG0"})
    assert len(one["analyses"]) == 1
    assert "Password:" in one["output"]

    batch = run("aaa\nbbb\n", {})
    assert len(batch["analyses"]) == 2
    assert "Password" in batch["output"] and "Score" in batch["output"]

    empty = run("\n\n", {})
    assert empty["analyses"] == []
    assert "No passwords" in empty["output"]


def test_run_exit_style_weak_password() -> None:
    bad = run("", {"single_password": "123"})
    assert bad["analyses"][0]["grade"] in {"Terrible", "Weak"}


def test_analyze_password_invalid_min_length_type() -> None:
    with pytest.raises(ParseError):
        analyze_password("x", {"min_length": "not-an-int"})


def test_analyze_password_min_length_below_one() -> None:
    with pytest.raises(ValidationError):
        analyze_password("x", {"min_length": 0})
