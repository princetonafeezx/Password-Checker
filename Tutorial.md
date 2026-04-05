# Build a Password Strength Analyzer in Python

This tutorial shows a new Python coder how to build a password strength analyzer like the one in the `Password-Checker` repository.

By the end, you will have a command-line app that can:

- analyze one password or many passwords from a file
- score passwords out of 100
- check length, character variety, common-password matches, sequences, repeats, keyboard patterns, and entropy
- print a readable report in the terminal
- export the full result as JSON

---

## 1. What you are building

You are building a **CLI app**.

CLI means **command-line interface**. Instead of clicking buttons, the user runs commands like this:

```bash
python -m password_checker --password "MyP@ssw0rd123"
python -m password_checker --file passwords.txt
```

The app will examine each password and return:

- a total score
- a grade such as `Weak`, `Fair`, or `Strong`
- per-rule results
- advice for improving weak passwords

---

## 2. Skills you will practice

This project is great for beginners because it teaches:

- Python functions
- lists and dictionaries
- string handling
- regular expressions
- command-line arguments with `argparse`
- reading and writing files
- JSON export
- splitting code into multiple modules

---

## 3. Project structure

Create a folder named `Password-Checker` and add these files:

```text
Password-Checker/
├── __main__.py
├── password_checker.py
├── formatter.py
├── common_passwords.py
├── errors.py
├── requirements.txt
└── tests/
```

You can add the `tests/` folder later. First, get the app working.

---

## 4. Set up your environment

Make sure Python is installed.

Check with:

```bash
python --version
```

Create the project folder:

```bash
mkdir Password-Checker
cd Password-Checker
```

Optional: create and activate a virtual environment.

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS / Linux

```bash
python -m venv .venv
source .venv/bin/activate
```

Create `requirements.txt`:

```txt
# Standard library only at runtime.
# For testing (optional but recommended)
pytest==8.0.0
```

Install the optional test dependency:

```bash
pip install -r requirements.txt
```

---

## 5. Create shared custom errors

Make a file named `errors.py`.

This keeps error handling clean and readable.

```python
"""Shared exceptions for the app."""


class DataGuardError(Exception):
    """Base exception for friendly CLI failures."""


class InputError(DataGuardError):
    """Raised when an input file cannot be read, or a report cannot be written."""


class ParseError(DataGuardError):
    """Raised when data cannot be parsed."""


class ValidationError(DataGuardError):
    """Raised when CLI arguments or options fail validation before analysis."""
```

### Why this file matters

Instead of raising generic errors everywhere, you create app-specific error types. That makes your program easier to debug and easier to explain to users.

---

## 6. Add a built-in password blacklist

Make a file named `common_passwords.py`.

This holds a small offline list of common passwords.

```python
"""A compact built-in list of very common passwords.

Curated for offline checks (not a full breach corpus).
"""

COMMON_PASSWORDS = [
    "123456",
    "123456789",
    "12345678",
    "12345",
    "111111",
    "123123",
    "1234567890",
    "qwerty",
    "password",
    "password1",
    "abc123",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "letmein",
    "football",
    "baseball",
    "sunshine",
    "master",
    "shadow",
    "ashley",
    "bailey",
    "access",
    "flower",
    "superman",
    "hello",
    "freedom",
    "whatever",
    "qazwsx",
    "trustno1",
    "654321",
    "121212",
    "000000",
    "batman",
    "charlie",
    "donald",
    "jessica",
    "michael",
    "jordan",
    "michelle",
    "loveme",
    "zaq12wsx",
    "passw0rd",
    "starwars",
    "computer",
    "internet",
    "qwertyuiop",
    "1q2w3e4r",
    "987654321",
    "123qwe",
    "mustang",
    "pokemon",
    "secret",
    "hottie",
    "ginger",
    "summer",
    "princess",
    "thomas",
    "tigger",
    "buster",
    "soccer",
    "killer",
    "pepper",
    "jennifer",
    "daniel",
    "andrew",
    "nicole",
    "joshua",
    "cheese",
    "maggie",
    "cookie",
    "matrix",
    "silver",
    "snoopy",
    "orange",
    "jasmine",
    "hunter",
    "dakota",
    "taylor",
    "merlin",
    "service",
    "testing",
    "changeme",
    "default",
    "administrator",
    "welcome1",
    "root",
    "pass123",
    "login",
    "secret123",
    "secure123",
    "q1w2e3r4",
    "asdfgh",
    "zxcvbn",
    "asdf1234",
    "temp123",
    "winter2024",
    "summer2024",
    "spring2024",
    "fall2024",
    "welcome123",
    "qwerty123",
]
```

### Why this file matters

A lot of weak passwords are weak because they are common, not just because they are short. This list catches easy guesses.

---

## 7. Build formatting helpers

Make a file named `formatter.py`.

This file handles:

- terminal colors
- ASCII tables
- text reports
- CSV reports
- JSON reports

Paste this in:

```python
"""Shared output and report formatting."""

from __future__ import annotations

import csv
import io
import json
import os
import sys

ANSI_COLORS = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}

SEVERITY_COLORS = {
    "critical": "magenta",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan",
}


def stream_supports_color(stream) -> bool:
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return True



def colorize(text: str, color: str, enabled: bool = True) -> str:
    if not enabled or color not in ANSI_COLORS:
        return text
    return f"{ANSI_COLORS[color]}{text}{ANSI_COLORS['reset']}"



def format_table(headers: list[str], rows: list[list[object]], borders: bool = False) -> str:
    string_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]

    for row in string_rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def render_row(row_values: list[str]) -> str:
        cells = [value.ljust(widths[index]) for index, value in enumerate(row_values)]
        if borders:
            return "| " + " | ".join(cells) + " |"
        return "  ".join(cells)

    lines = [render_row(headers)]
    divider_parts = ["-" * width for width in widths]

    if borders:
        lines.append("|-" + "-|-".join(divider_parts) + "-|")
    else:
        lines.append("  ".join(divider_parts))

    for row in string_rows:
        lines.append(render_row(row))

    return "\n".join(lines)



def findings_to_rows(findings: list[dict]) -> list[list[object]]:
    rows = []
    for finding in findings:
        rows.append([
            finding.get("severity", "info"),
            finding.get("category", ""),
            finding.get("line", ""),
            finding.get("message", ""),
        ])
    return rows



def render_report_text(result: dict, color_enabled: bool = True) -> str:
    lines = []
    title = result.get("title") or result.get("module_name", "Password Report")
    lines.append(title)
    lines.append("=" * len(title))

    metadata = result.get("metadata", {})
    if metadata:
        for key, value in metadata.items():
            lines.append(f"{key}: {value}")

    stats = result.get("stats", {})
    if stats:
        lines.append("")
        lines.append("Stats")
        lines.append("-----")
        for key, value in stats.items():
            lines.append(f"{key}: {value}")

    findings = result.get("findings", [])
    if findings:
        lines.append("")
        lines.append("Findings")
        lines.append("--------")
        rendered_rows = []
        for row in findings_to_rows(findings):
            severity = row[0]
            color = SEVERITY_COLORS.get(severity, "cyan")
            row[0] = colorize(severity, color, color_enabled)
            rendered_rows.append(row)
        lines.append(format_table(["Severity", "Category", "Line", "Message"], rendered_rows))

    warnings = result.get("warnings", [])
    if warnings:
        lines.append("")
        lines.append("Warnings")
        lines.append("--------")
        for warning in warnings:
            lines.append(f"- {warning}")

    errors = result.get("errors", [])
    if errors:
        lines.append("")
        lines.append("Errors")
        lines.append("------")
        for error in errors:
            lines.append(f"- {error}")

    summary = result.get("summary")
    if summary:
        lines.append("")
        lines.append(f"Summary: {summary}")

    return "\n".join(lines).strip()



def render_report_csv(result: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["severity", "category", "line", "message"])
    for finding in result.get("findings", []):
        writer.writerow([
            finding.get("severity", "info"),
            finding.get("category", ""),
            finding.get("line", ""),
            finding.get("message", ""),
        ])
    return buffer.getvalue()



def render_report(result: dict, report_format: str = "text", color_enabled: bool = True) -> str:
    if report_format == "json":
        return json.dumps(result, indent=2, ensure_ascii=False)
    if report_format == "csv":
        return render_report_csv(result)
    return render_report_text(result, color_enabled=color_enabled)



def write_report(
    result: dict,
    report_format: str = "text",
    color_enabled: bool = True,
    report_file: str | None = None,
) -> None:
    rendered = render_report(result, report_format=report_format, color_enabled=color_enabled)
    if report_file:
        with open(report_file, "w", encoding="utf-8", newline="") as handle:
            handle.write(rendered)
            if not rendered.endswith("\n"):
                handle.write("\n")
        return

    sys.stderr.write(rendered)
    if not rendered.endswith("\n"):
        sys.stderr.write("\n")



def serialize_primary_output(output, pipe_format: str = "text") -> str:
    if pipe_format == "raw":
        if isinstance(output, (dict, list)):
            try:
                return json.dumps(output, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                return str(output)
        return str(output)

    if pipe_format == "json":
        try:
            return json.dumps(output, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(output)

    if isinstance(output, (dict, list)):
        return json.dumps(output, indent=2, ensure_ascii=False)

    return str(output)
```

### What this file teaches

- helper functions
- using dictionaries for configuration
- generating plain-text tables
- exporting structured data

---

## 8. Build the core password analyzer

Now create `password_checker.py`.

This is the heart of the app.

It will:

- inspect a password
- run several rule checks
- total the score
- choose a grade
- return all results as a dictionary

Paste this in:

```python
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
LEET_MAP = str.maketrans({
    "@": "a",
    "4": "a",
    "3": "e",
    "1": "i",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
})

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
        chunk = lowered[index:index + 3]
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
                chunk = row[index:index + window_size]
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
        rule_results.append({
            "name": "dictionary",
            "points": 20,
            "max_points": 20,
            "passed": True,
            "details": "Dictionary check skipped by flag.",
            "feedback": "Dictionary check skipped.",
        })

    rule_results.extend([
        check_sequences(password),
        check_repeats(password),
        check_keyboard_patterns(password),
    ])

    if include_entropy:
        rule_results.append(calculate_entropy(password))
    else:
        rule_results.append({
            "name": "entropy",
            "points": 15,
            "max_points": 15,
            "passed": True,
            "details": "Entropy calculation skipped by flag.",
            "feedback": "Entropy calculation skipped.",
            "entropy_bits": None,
        })

    score = int(sum(rule["points"] for rule in rule_results))
    grade = grade_from_score(score)

    return {
        "password": password,
        "score": score,
        "grade": grade,
        "rules": rule_results,
        "feedback": top_feedback(rule_results),
        "entropy_bits": next(
            (rule.get("entropy_bits") for rule in rule_results if rule["name"] == "entropy"),
            None,
        ),
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
        rows.append([
            mask_password(analysis["password"], show_password),
            analysis["score"],
            analysis["grade"],
            top_issue,
        ])
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
            findings.append({
                "severity": "medium",
                "category": "weak_password",
                "line": index,
                "message": f"Password at line {index} scored {analysis['score']} ({analysis['grade']}).",
            })

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
        "metadata": {
            "source": config.get("source_name", "<input>"),
            "minimum_length": int(config.get("min_length", 8)),
        },
        "summary": summary,
    }


if __name__ == "__main__":
    import runpy
    from pathlib import Path

    runpy.run_path(str(Path(__file__).resolve().with_name("__main__.py")), run_name="__main__")
```

---

## 9. Understand the scoring system

This app scores passwords out of **100**.

| Rule | Max points |
|------|------------|
| Length | 20 |
| Character diversity | 20 |
| Dictionary match | 20 |
| No simple sequences | 10 |
| No repeated streaks | 5 |
| No keyboard patterns | 10 |
| Entropy estimate | 15 |

Grades:

- `Fortress` = 85+
- `Strong` = 70+
- `Fair` = 50+
- `Weak` = 30+
- `Terrible` = below 30

### Why this design works

Instead of only saying “good” or “bad,” the app scores several behaviors. That gives the user more helpful feedback.

---

## 10. Build the command-line interface

Now create `__main__.py`.

This file lets the user run the app from the terminal.

```python
"""Command-line entry for the password strength analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from errors import DataGuardError, InputError, ValidationError
from formatter import colorize, stream_supports_color, write_report
from password_checker import run

GRADE_COLORS = {
    "Terrible": "red",
    "Weak": "red",
    "Fair": "yellow",
    "Strong": "green",
    "Fortress": "green",
}


def colorize_grade_line(text: str, *, color_enabled: bool) -> str:
    if not color_enabled:
        return text

    lines = text.splitlines()
    out = []
    prefix = "Grade: "

    for line in lines:
        if line.startswith(prefix):
            grade = line[len(prefix):].strip()
            color = GRADE_COLORS.get(grade)
            if color:
                line = f"{prefix}{colorize(grade, color, True)}"
        out.append(line)

    return "\n".join(out)



def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score passwords with layered rules (length, diversity, dictionary, patterns, entropy).",
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--password",
        "-p",
        metavar="TEXT",
        help="Analyze one password (masked in output unless --show).",
    )
    src.add_argument(
        "--file",
        "-f",
        type=Path,
        metavar="PATH",
        help="Batch mode: read one password per non-empty line.",
    )

    parser.add_argument(
        "--show",
        action="store_true",
        help="Show real passwords in output instead of masking.",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=8,
        metavar="N",
        help="Minimum length target for scoring (default: 8).",
    )
    parser.add_argument(
        "--no-dictionary",
        action="store_true",
        help="Skip the built-in common-password dictionary check.",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Skip entropy calculation.",
    )
    parser.add_argument(
        "--export",
        type=Path,
        metavar="PATH",
        help="Write the full report as JSON to this path.",
    )
    parser.add_argument(
        "--source-name",
        default=None,
        metavar="LABEL",
        help="Metadata label for the report (default: file path or <cli --password>).",
    )

    return parser.parse_args(argv)



def exit_code_from_result(result: dict) -> int:
    for analysis in result.get("analyses") or []:
        if analysis.get("grade") in {"Terrible", "Weak"}:
            return 1
    return 0



def main(argv: list[str] | None = None) -> int:
    try:
        return _main_impl(argv)
    except ValidationError as exc:
        print(f"password_checker: {exc}", file=sys.stderr)
        return 2
    except InputError as exc:
        print(f"password_checker: {exc}", file=sys.stderr)
        return 2
    except DataGuardError as exc:
        print(f"password_checker: {exc}", file=sys.stderr)
        return 2



def _main_impl(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.min_length < 1:
        raise ValidationError("--min-length must be at least 1")

    stdout_color = stream_supports_color(sys.stdout)

    if args.password is not None:
        input_text = ""
        default_source = "<cli --password>"
        config = {
            "show_password": args.show,
            "min_length": args.min_length,
            "no_dictionary": args.no_dictionary,
            "no_entropy": args.no_entropy,
            "source_name": args.source_name or default_source,
            "single_password": args.password,
        }
    else:
        try:
            input_text = args.file.read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"cannot read {args.file}: {exc}") from exc

        default_source = str(args.file.resolve())
        config = {
            "show_password": args.show,
            "min_length": args.min_length,
            "no_dictionary": args.no_dictionary,
            "no_entropy": args.no_entropy,
            "source_name": args.source_name or default_source,
        }

    result = run(input_text, config)
    primary = result.get("output", "")

    if primary.startswith("Password:"):
        primary = colorize_grade_line(primary, color_enabled=stdout_color)

    sys.stdout.write(primary)
    if primary and not primary.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()

    write_report(
        result,
        report_format="text",
        color_enabled=stream_supports_color(sys.stderr),
        report_file=None,
    )

    if args.export is not None:
        try:
            write_report(
                result,
                report_format="json",
                color_enabled=False,
                report_file=str(args.export),
            )
        except OSError as exc:
            raise InputError(f"cannot write {args.export}: {exc}") from exc

    return exit_code_from_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
```

### What this file teaches

- parsing command-line flags
- reading file input
- returning exit codes
- friendly error messages
- controlling text output

---

## 11. How the files work together

Here is the flow:

1. The user runs a command.
2. `__main__.py` reads the arguments.
3. It builds a `config` dictionary.
4. It calls `run()` from `password_checker.py`.
5. `run()` analyzes one or more passwords.
6. It returns a result dictionary.
7. `__main__.py` prints the main output and optional report export.

That is a strong beginner project pattern:

- one file for CLI
- one file for business logic
- one file for formatting
- one file for constants/data
- one file for shared exceptions

---

## 12. Run your app

Try a single password:

```bash
python -m password_checker --password "password123"
```

Try showing the password instead of masking it:

```bash
python -m password_checker --password "MyBetterP@ssw0rd!" --show
```

Use a higher minimum length:

```bash
python -m password_checker --password "MyBetterP@ssw0rd!" --min-length 12
```

Skip the dictionary check:

```bash
python -m password_checker --password "password123" --no-dictionary
```

Skip entropy:

```bash
python -m password_checker --password "password123" --no-entropy
```

---

## 13. Run batch mode

Create a file named `passwords.txt`:

```txt
password
P@ssword123
CorrectHorseBatteryStaple!
abc123
```

Now run:

```bash
python -m password_checker --file passwords.txt
```

You should get a table with columns like:

- password
- score
- grade
- top issue

---

## 14. Export JSON

To export the full report:

```bash
python -m password_checker --file passwords.txt --export report.json
```

This writes a machine-readable JSON file. That is useful if you want to:

- send results to another program
- save reports
- build a web version later
- feed results into dashboards or automation

---

## 15. What each rule is doing

### Length check

Longer passwords are usually harder to brute-force.

### Diversity check

Mixing lowercase, uppercase, digits, and symbols increases the search space.

### Dictionary check

Passwords like `password`, `admin`, and `qwerty123` are easy to guess.

### Sequence check

Patterns like `abc`, `123`, and `cba` are predictable.

### Repeat check

Streaks like `aaa` or `111` are weak patterns.

### Keyboard pattern check

Strings like `qwerty`, `asdf`, and `12345` follow keyboard rows and are common.

### Entropy estimate

This estimates how many bits of randomness a password appears to have based on its length and character pool.

---

## 16. Beginner notes on regular expressions used here

This project uses `re`, Python’s regular expression module.

Examples from the app:

```python
re.search(r"[a-z]", password)
```

Checks whether the password contains at least one lowercase letter.

```python
re.search(r"\d", password)
```

Checks whether the password contains at least one digit.

```python
re.search(r"(.)\1{2,}", password)
```

This finds 3 or more repeated characters in a row.

- `(.)` captures any character
- `\1` means “the same captured character again”
- `{2,}` means repeat 2 or more more times after the first one

So `aaa`, `111`, or `$$$$` will match.

---

## 17. Why the app returns dictionaries

A beginner might ask: why not just print everything directly?

Because returning dictionaries gives you flexibility.

For example, `analyze_password()` returns structured data like:

```python
{
    "password": "example123",
    "score": 52,
    "grade": "Fair",
    "rules": [...],
    "feedback": [...],
    "entropy_bits": 41.5,
}
```

That structure is easy to:

- print
- export as JSON
- test
- reuse in a future web app

This is a very good habit for new developers.

---

## 18. Add tests

Create a folder named `tests`.

Inside it, create `tests/test_password_checker.py`.

Use these starter tests:

```python
from password_checker import analyze_password, run


def test_common_password_is_weak():
    result = analyze_password("password", {"min_length": 8})
    assert result["grade"] in {"Terrible", "Weak", "Fair"}
    assert any(rule["name"] == "dictionary" and not rule["passed"] for rule in result["rules"])



def test_strong_password_scores_higher():
    weak = analyze_password("abc123", {"min_length": 8})
    strong = analyze_password("R!verStone42$Moon", {"min_length": 8})
    assert strong["score"] > weak["score"]



def test_batch_mode_counts_passwords():
    text = "password\nBetterPass123!\n"
    result = run(text, {"source_name": "test.txt"})
    assert result["stats"]["passwords_analyzed"] == 2
```

Run tests with:

```bash
python -m pytest tests/ -q
```

---

## 19. Common beginner mistakes

### Mistake: naming conflict with module imports

If your file names do not match the imports, Python will fail.

Use exactly these names:

- `password_checker.py`
- `formatter.py`
- `common_passwords.py`
- `errors.py`
- `__main__.py`

### Mistake: running commands from the wrong folder

Run commands from inside the project folder so imports work.

### Mistake: forgetting the raw string in regex

Use `r"..."` for regex patterns.

### Mistake: using tabs and spaces inconsistently

Stick to 4 spaces per indentation level.

### Mistake: not handling empty input

The `run()` function already handles empty input safely.

---

## 20. Suggested build order for a beginner

Follow this order exactly:

1. create `errors.py`
2. create `common_passwords.py`
3. create `formatter.py`
4. create `password_checker.py`
5. create `__main__.py`
6. test a single password
7. test batch mode
8. test JSON export
9. add `tests/`

This order keeps the project manageable.

---

## 21. How to extend the app later

Once the basic app works, try these upgrades:

- add more common passwords
- add support for passphrase checks
- add CSV export of full analyses, not just findings
- build a Flask or FastAPI web version
- add a progress bar for large input files
- detect dates like birthdays or years
- detect repeated words
- add clipboard-safe masking rules

---

## 22. Final review checklist

Before you compare your version to the repository, make sure your app can do all of this:

- [ ] analyze one password from the CLI
- [ ] analyze many passwords from a file
- [ ] mask passwords unless `--show` is used
- [ ] score passwords out of 100
- [ ] grade each password
- [ ] detect dictionary matches
- [ ] detect sequences
- [ ] detect repeated streaks
- [ ] detect keyboard walks
- [ ] estimate entropy
- [ ] export JSON report
- [ ] return sensible exit codes

---

## 23. Example commands to verify your build

```bash
python -m password_checker --password "password"
python -m password_checker --password "StrongerP@ssword42!" --show
python -m password_checker --file passwords.txt
python -m password_checker --file passwords.txt --export report.json
```

---

## 24. What you learned

By building this project, you practiced real-world Python patterns:

- modular project structure
- reusable business logic
- command-line tooling
- data validation
- simple security heuristics
- text formatting
- JSON export
- automated tests

That is a strong beginner portfolio project because it is small enough to understand, but real enough to demonstrate useful engineering skills.

---

## 25. Next step

After you finish this tutorial, compare your files with the original repository and look for differences in:

- naming
- comments
- output formatting
- scoring details
- code organization

That comparison step is where a lot of learning happens.
