"""Password strength analyzer."""

from __future__ import annotations

import math
import re
import string

from errors import ParseError, ValidationError
from common_passwords import COMMON_PASSWORDS
from formatter import format_table

COMMON_PASSWORDS_LOWER = frozenset(entry.lower() for entry in COMMON_PASSWORDS)









def run() -> dict:
    pass

if __name__ == "__main__":
    import runpy
    from pathlib import Path

    runpy.run_path(str(Path(__file__).resolve().with_name("__main__.py")), run_name="__main__")