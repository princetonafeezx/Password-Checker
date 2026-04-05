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








def run() -> dict:
    pass

if __name__ == "__main__":
    import runpy
    from pathlib import Path

    runpy.run_path(str(Path(__file__).resolve().with_name("__main__.py")), run_name="__main__")