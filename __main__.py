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
        config: dict = {
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




















if __name__ == "__main__":
    raise SystemExit(main())