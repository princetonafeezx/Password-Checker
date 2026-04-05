# Password strength analyzer

CLI and library that scores passwords with layered rules: length, character-class diversity, a **small offline** common-password list, sequential runs, repeated streaks, horizontal QWERTY-row walks, and a length × pool-size entropy estimate. Output includes per-rule results and prioritized suggestions (by point deficit), not only a single “strong/weak” label.

**Scope:** Heuristic audit helper for learning and local checks. It is **not** a substitute for breach APIs (for example [Have I Been Pwned](https://haveibeenpwned.com/)), enterprise policy engines, or cryptographically random secret generation.

---

## Usage

Run from this directory (so `password_checker.py` and `formatter.py` resolve on the import path):

```bash
python -m password_checker --password "your_secret_here"
python -m password_checker --file passwords.txt
```

**PowerShell:** ``$`` inside double-quoted arguments starts variable expansion. Prefer **single-quoted** passwords when the secret contains ``$`` (for example ``--password 'my$ecret'``).

Or execute the CLI module directly:

```bash
python __main__.py --password "your_secret_here"
```

Primary analysis is written to **stdout**; the titled report (metadata, stats, summary) goes to **stderr**—so you can pipe stdout while still seeing the summary on the terminal.

### CLI flags

| Flag | Purpose |
|------|---------|
| `--password` / `-p` | Analyze one password (masked unless `--show`). |
| `--file` / `-f` | Batch mode: one non-empty line per password. |
| `--show` | Show real passwords in the table or single-password block. |
| `--min-length N` | Minimum length target for scoring (default `8`). |
| `--no-dictionary` | Skip the built-in common-password check (still scores other rules). |
| `--no-entropy` | Skip entropy calculation; that rule is reported as skipped and still receives full points (total remains out of 100). |
| `--export PATH` | Write the **full** report as JSON to `PATH`. |
| `--source-name LABEL` | Metadata `source` field (default: file path or `<cli --password>`). |

**Exit codes:** `0` if every password scores **Fair** or better; `1` if any line scores **Weak** or **Terrible**; `2` if the input file cannot be read or written, or if options fail validation (for example `--min-length` &lt; 1).

**Colors (single-password block):** When stdout is a TTY and `NO_COLOR` is unset, the `Grade:` line uses red (Terrible/Weak), yellow (Fair), green (Strong/Fortress). Batch table output is plain text.

---

## Library API

```python
from password_checker import analyze_password, run

analysis = analyze_password("example", {"min_length": 12})
report = run("line1\nline2\n", {"source_name": "demo.txt"})
```

Invalid ``min_length`` in ``config`` (non-integer or &lt; 1) raises ``ParseError`` or ``ValidationError`` from ``errors.py``. ``run()`` propagates those exceptions from ``analyze_password()``.

`run()` returns a dict suitable for `formatter.write_report()` / `formatter.render_report()` (text, JSON, or CSV).

---

## Scoring (100 points when all rules are enabled)

| Rule | Max points |
|------|------------|
| Length | 20 |
| Character diversity (lower / upper / digit / symbol) | 20 |
| Not in common-password set | 20 |
| No 3-char ascending/descending sequences | 10 |
| No 3+ repeated character streak | 5 |
| No QWERTY-row keyboard walk (3–5 chars) | 10 |
| Entropy estimate | 15 |

**Grades:** Fortress ≥ 85, Strong ≥ 70, Fair ≥ 50, Weak ≥ 30, Terrible &lt; 30.

**Dictionary:** `common_passwords.COMMON_PASSWORDS` is a **curated** offline list (on the order of 100 entries), not a full breach corpus. Extend it for stricter offline checks.

**Leet normalization:** Before dictionary matching, common substitutions (`@→a`, `0→o`, etc.) are applied so trivial variants of list entries are still caught.

**Entropy:** Uses \(L \cdot \log_2(R)\) with \(R\) = size of the union of character classes present. This models **uniform random** choices from that pool; natural language or memorable phrases can be easier to guess than their bit score suggests—hence the dictionary and pattern rules.

---

## Project layout

| File | Role |
|------|------|
| `password_checker.py` | Rules, `analyze_password()`, `run()`. |
| `__main__.py` | `argparse` CLI. |
| `formatter.py` | Tables, colored report, JSON/CSV export helpers. |
| `common_passwords.py` | `COMMON_PASSWORDS` list. |
| `errors.py` | Shared exception types (for callers that need them). |

Tables use `formatter.format_table` (stdlib only); there is no third-party runtime dependency.

---

## Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -q
```

---

## Integration note

This repo is suitable as a standalone auditor or as a module wired into a larger pipeline (for example a DataGuard-style credential check). Keep README claims aligned with the actual list size and heuristic nature of the score.
