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









def main():
    pass


if __name__ == "__main__":
    raise SystemExit(main())