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
    out: list[str] = []
    prefix = "Grade: "
    for line in lines:
        if line.startswith(prefix):
            grade = line[len(prefix) :].strip()
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









def main():
    pass


if __name__ == "__main__":
    raise SystemExit(main())