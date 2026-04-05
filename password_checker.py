"""Password strength analyzer."""

from __future__ import annotations

import math
import re
import string

from errors import ParseError, ValidationError
from common_passwords import COMMON_PASSWORDS
from formatter import format_table

COMMON_PASSWORDS_LOWER = frozenset(entry.lower() for entry in COMMON_PASSWORDS)
KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "0": "o", "$": "s", "5": "s", "7": "t"})

GRADE_BANDS = [
    (85, "Fortress"),
    (70, "Strong"),
    (50, "Fair"),
    (30, "Weak"),
    (0, "Terrible"),
]

def mask_password(password: str, show_password: bool) -> str:
    if show_password:
        return password
    if not password:
        return "<empty>"
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]

def normalized_password(password: str) -> str:
    return password.lower().translate(LEET_MAP)

def check_length(password: str, min_length: int) -> dict:
    length = len(password)
    if length >= 20:
        points = 20
    elif length >= min_length:
        points = min(20, 12 + (length - min_length) * 1.0)
    else:
        points = max(0, int((length / max(min_length, 1)) * 12))
    return {
        "name": "length",
        "points": int(points),
        "max_points": 20,
        "passed": length >= min_length,
        "details": f"Length is {length}; minimum target is {min_length}.",
        "feedback": f"Add at least {max(min_length - length, 0)} more characters." if length < min_length else "Good length coverage.",
    }

def check_diversity(password: str) -> dict:
    classes = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "symbols": bool(re.search(rf"[{re.escape(string.punctuation)}]", password)),
    }
    class_count = sum(classes.values())
    points = class_count * 5
    missing = [name for name, present in classes.items() if not present]
    return {
        "name": "diversity",
        "points": points,
        "max_points": 20,
        "passed": class_count >= 3,
        "details": f"Uses {class_count} character classes.",
        "feedback": "Add " + ", ".join(missing[:2]) + "." if missing else "Good character diversity.",
    }

def check_dictionary(password: str) -> dict:
    lowered = password.lower()
    leet_normalized = normalized_password(password)
    exact_match = lowered in COMMON_PASSWORDS_LOWER
    leet_match = leet_normalized in COMMON_PASSWORDS_LOWER
    passed = not (exact_match or leet_match)
    return {
        "name": "dictionary",
        "points": 20 if passed else 0,
        "max_points": 20,
        "passed": passed,
        "details": "Compared against the built-in common-password dictionary.",
        "feedback": "Choose something less common than a top-list password." if not passed else "Good: no common dictionary matches found.",
    }

def detect_sequences(password: str) -> list[str]:
    sequences = []
    lowered = password.lower()
    for index in range(len(lowered) - 2):
        chunk = lowered[index : index + 3]
        if len(set(chunk)) == 1:
            continue
        diffs = [ord(chunk[position + 1]) - ord(chunk[position]) for position in range(2)]
        if diffs == [1, 1] or diffs == [-1, -1]:
            sequences.append(chunk)
    return sequences

def check_sequences(password: str) -> dict:
    sequences = detect_sequences(password)
    passed = not sequences
    detail = "No ascending or descending 3-character sequences found." if passed else f"Found sequences: {', '.join(sequences[:3])}."
    feedback = "Avoid predictable runs like abc or 321." if not passed else "No simple sequences detected."
    return {
        "name": "sequences",
        "points": 10 if passed else 0,
        "max_points": 10,
        "passed": passed,
        "details": detail,
        "feedback": feedback,
    }

def check_repeats(password: str) -> dict:
    match = re.search(r"(.)\1{2,}", password)
    passed = match is None
    return {
        "name": "repeats",
        "points": 5 if passed else 0,
        "max_points": 5,
        "passed": passed,
        "details": "No repeated 3-character streaks found." if passed else f"Repeated streak {match.group(0)!r} is guessable.",
        "feedback": "Break up repeated characters like aaa or 111." if not passed else "No repeated streaks detected.",
    }

def detect_keyboard_patterns(password: str) -> list[str]:
    found = []
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for window_size in range(3, min(6, len(row)) + 1):
            for index in range(len(row) - window_size + 1):
                chunk = row[index : index + window_size]
                # Check both forward (qwerty) and backward (ytrewq)
                if chunk in lowered or chunk[::-1] in lowered:
                    found.append(chunk)
    return found

def check_keyboard_patterns(password: str) -> dict:
    patterns = detect_keyboard_patterns(password)
    passed = not patterns
    return {
        "name": "keyboard_patterns",
        "points": 10 if passed else 0,
        "max_points": 10,
        "passed": passed,
        "details": "No obvious keyboard walks found." if passed else f"Found keyboard patterns like {patterns[0]!r}.",
        "feedback": "Avoid keyboard walks like qwerty or asdf." if not passed else "No keyboard walks detected.",
    }

def character_pool_size(password: str) -> int:
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"\d", password):
        pool_size += 10
    if re.search(rf"[{re.escape(string.punctuation)}]", password):
        pool_size += len(string.punctuation)
    return max(pool_size, 1)

def calculate_entropy(password: str) -> dict:
    pool_size = character_pool_size(password)
    entropy_bits = len(password) * math.log2(pool_size)
    if entropy_bits >= 80:
        points = 15
        label = "Excellent"
    elif entropy_bits >= 60:
        points = 12
        label = "Strong"
    elif entropy_bits >= 40:
        points = 8
        label = "Moderate"
    else:
        points = 3
        label = "Low"
    return {
        "name": "entropy",
        "points": points,
        "max_points": 15,
        "passed": entropy_bits >= 40,
        "details": f"Estimated entropy is {entropy_bits:.1f} bits ({label}).",
        "feedback": "Increase length and character variety to raise entropy." if entropy_bits < 40 else "Entropy looks healthy.",
        "entropy_bits": round(entropy_bits, 1),
    }

def grade_from_score(score: int) -> str:
    for threshold, label in GRADE_BANDS:
        if score >= threshold:
            return label
    return "Terrible"

def top_feedback(rule_results: list[dict]) -> list[str]:
    failed_rules = [rule for rule in rule_results if not rule["passed"]]
    failed_rules.sort(key=lambda item: item["max_points"] - item["points"], reverse=True)
    return [rule["feedback"] for rule in failed_rules[:3]]

def analyze_password(password: str, config: dict) -> dict:
    raw_min = config.get("min_length", 8)
    try:
        min_length = int(raw_min)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"min_length must be an integer, got {raw_min!r}") from exc
    if min_length < 1:
        raise ValidationError("min_length must be at least 1")

    include_dictionary = not config.get("no_dictionary", False)
    include_entropy = not config.get("no_entropy", False)
    
    rule_results = [
        check_length(password, min_length),
        check_diversity(password),
    ]
    if include_dictionary:
        rule_results.append(check_dictionary(password))
    else:
        rule_results.append(
            {
                "name": "dictionary",
                "points": 20,
                "max_points": 20,
                "passed": True,
                "details": "Dictionary check skipped by flag.",
                "feedback": "Dictionary check skipped.",
            }
        )
    rule_results.extend(
        [
            check_sequences(password),
            check_repeats(password),
            check_keyboard_patterns(password),
        ]
    )
    if include_entropy:
        rule_results.append(calculate_entropy(password))
    else:
        rule_results.append(
            {
                "name": "entropy",
                "points": 15,
                "max_points": 15,
                "passed": True,
                "details": "Entropy calculation skipped by flag.",
                "feedback": "Entropy calculation skipped.",
                "entropy_bits": None,
            }
        )
    
    score = int(sum(rule["points"] for rule in rule_results))
    grade = grade_from_score(score)
    return {
        "password": password,
        "score": score,
        "grade": grade,
        "rules": rule_results,
        "feedback": top_feedback(rule_results),
        "entropy_bits": next((rule.get("entropy_bits") for rule in rule_results if rule["name"] == "entropy"), None),
    }


def render_single_analysis(analysis: dict, show_password: bool) -> str:
    lines = [
        f"Password: {mask_password(analysis['password'], show_password)}",
        f"Score: {analysis['score']}/100",
        f"Grade: {analysis['grade']}",
    ]
    if analysis["entropy_bits"] is not None:
        lines.append(f"Entropy: {analysis['entropy_bits']:.1f} bits")
    lines.append("")
    lines.append("Rule checks:")
    for rule in analysis["rules"]:
        status = "PASS" if rule["passed"] else "FAIL"
        lines.append(f"- {rule['name']}: {status} ({rule['points']}/{rule['max_points']})")
        lines.append(f"  {rule['details']}")
    if analysis["feedback"]:
        lines.append("")
        lines.append("Top advice:")
        for item in analysis["feedback"]:
            lines.append(f"- {item}")
    return "\n".join(lines)

def render_batch_analysis(analyses: list[dict], show_password: bool) -> str:
    rows = []
    for analysis in analyses:
        top_issue = analysis["feedback"][0] if analysis["feedback"] else "Looks healthy."
        rows.append(
            [
                mask_password(analysis["password"], show_password),
                analysis["score"],
                analysis["grade"],
                top_issue,
            ]
        )
    return format_table(["Password", "Score", "Grade", "Top issue"], rows)


def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    if config.get("single_password") is not None:
        passwords = [config["single_password"]]
    else:
        passwords = [line.rstrip("\n") for line in input_text.splitlines() if line.strip()]
    
    analyses = [analyze_password(password, config) for password in passwords]
    if not analyses:
        output = "No passwords to analyze.\n"
    elif len(analyses) == 1:
        output = render_single_analysis(analyses[0], bool(config.get("show_password")))
    else:
        output = render_batch_analysis(analyses, bool(config.get("show_password")))
    
    below_fair = [analysis for analysis in analyses if analysis["grade"] in {"Terrible", "Weak"}]
    weakest = min(analyses, key=lambda item: item["score"], default=None)
    average_score = round(sum(item["score"] for item in analyses) / max(len(analyses), 1), 1)

    findings = []
    for index, analysis in enumerate(analyses, start=1):
        if analysis["grade"] in {"Terrible", "Weak"}:
            findings.append(
                {
                    "severity": "medium",
                    "category": "weak_password",
                    "line": index,
                    "message": f"Password at line {index} scored {analysis['score']} ({analysis['grade']}).",
                }
            )

    summary = (
        f"Analyzed {len(analyses)} password(s); average score {average_score:.1f}. "
        f"{len(below_fair)} password(s) fell below Fair."
    )

    return {
        "module_name": "audit",
        "title": "DataGuard Password Audit Report",
        "output": output,
        "analyses": analyses,
        "findings": findings,
        "warnings": [f"{len(below_fair)} password(s) scored Weak or Terrible."] if below_fair else [],
        "errors": [],
        "stats": {
            "passwords_analyzed": len(analyses),
            "average_score": average_score,
            "weakest_line": analyses.index(weakest) + 1 if weakest else "",
            "below_fair": len(below_fair),
        },
        "metadata": {"source": config.get("source_name", "<input>"), "minimum_length": int(config.get("min_length", 8))},
        "summary": summary,
    }


if __name__ == "__main__":
    import runpy
    from pathlib import Path

    runpy.run_path(str(Path(__file__).resolve().with_name("__main__.py")), run_name="__main__")