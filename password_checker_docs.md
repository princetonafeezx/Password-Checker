# Architecture Decision Record
## App 06 — Password Checker
**DataGuard Group | Document 1 of 5**
**Status: Accepted**

---

## Context

DataGuard processes user-supplied data that frequently includes passwords — API keys, login credentials, default passwords in configuration files. The Password Checker is the sixth module in the DataGuard group, responsible for analyzing password strength using a layered rule system and producing actionable, scored reports. It must work both as a library called by the bootstrapper and as a standalone CLI tool for batch auditing.

---

## Decisions

### Decision 1 — Layered rule system with independent scores

**Chosen:** Seven independent checks — `length`, `diversity`, `dictionary`, `sequences`, `repeats`, `keyboard_patterns`, `entropy` — each returning a dict with `points`, `max_points`, `passed`, `details`, and `feedback`. Final score is the sum of all rule points.

**Rejected:** A single holistic scoring function.

**Reason:** Independent rules are independently testable, independently skippable (`no_dictionary`, `no_entropy` flags), and produce independent feedback. A monolithic function would make it impossible to test whether, say, the dictionary check correctly identifies leet substitutions without also running all other checks. The test suite confirms this — each rule has its own test function.

---

### Decision 2 — Leet-speak normalization for dictionary lookups

**Chosen:** `LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "0": "o", "$": "s", "5": "s", "7": "t"})`. `check_dictionary()` compares both the lowercased original and the leet-normalized form against `COMMON_PASSWORDS_LOWER`.

**Rejected:** Checking only the exact lowercase form.

**Reason:** `P@ssw0rd` is `password` in leet-speak — the most common substitution. Any dictionary check that fails to normalize leet substitutions would miss the majority of dictionary-based attempts. `test_check_dictionary_exact_and_leet` confirms both paths are covered.

---

### Decision 3 — `COMMON_PASSWORDS_LOWER` as a `frozenset` computed at import

**Chosen:** `COMMON_PASSWORDS_LOWER = frozenset(entry.lower() for entry in COMMON_PASSWORDS)` computed once at module load. Dictionary checks are O(1) membership tests.

**Rejected:** Computing the set inside `check_dictionary()` on every call, or keeping the list as a list.

**Reason:** The common password list is used on every call to `check_dictionary()`. Computing the frozenset inside the function would rebuild it on every password analyzed. List membership testing is O(n). A frozenset computed once at import time gives O(1) lookups at zero per-call cost. This is the Amendment 3.3 pattern — static data with a lightweight transformation applied once.

---

### Decision 4 — Grade bands with named thresholds

**Chosen:** `GRADE_BANDS = [(85, "Fortress"), (70, "Strong"), (50, "Fair"), (30, "Weak"), (0, "Terrible")]`. `grade_from_score()` iterates and returns the first matching label.

**Rejected:** A numeric score only, with no label.

**Reason:** Numeric scores require operators to memorize thresholds. Named grades provide immediate semantic meaning — "Weak" communicates action required without reading documentation. The `GRADE_COLORS` in `__main__.py` map these names to ANSI colors, making the CLI output visually scannable.

---

### Decision 5 — Exit code from grade, not from score

**Chosen:** `exit_code_from_result()` returns `1` if any analyzed password is graded `Terrible` or `Weak`, `0` otherwise.

**Rejected:** Exit code based on a numeric score threshold.

**Reason:** Exit codes are used in CI/CD pipelines and shell scripts. The binary signal needed by these callers is "did any password fail the minimum bar?" not "what was the average score?". The grade-based check maps directly to the Fair/Weak boundary — the natural semantic threshold between acceptable and unacceptable.

---

### Decision 6 — `single_password` config key to distinguish CLI mode from file mode

**Chosen:** When `--password` is used, the CLI sets `config["single_password"]` and passes `input_text=""`. `run()` checks `if config.get("single_password") is not None` to determine whether to use the config value or split the input text.

**Rejected:** Passing the single password as the first line of `input_text`.

**Reason:** Passing the password as `input_text` would require a special-case in the batch renderer to know not to render a table for one entry. The `single_password` key is an explicit signal — callers can distinguish the two modes without parsing the input. The test `test_run_single_vs_batch_and_empty_file` validates all three branches.

---

### Decision 7 — `__main__.py` as the CLI layer, `password_checker.py` as the engine

**Chosen:** The engine module (`password_checker.py`) contains no CLI code — no `argparse`, no `sys.argv`, no `sys.stdout.write`. All CLI logic, color application, and output routing lives in `__main__.py`.

**Rejected:** A single combined file.

**Reason:** The engine must be importable as a library without triggering CLI behavior. The bootstrapper imports `password_checker.run` directly. Having CLI code in the same file would require import-time execution guards. The `__main__.py` separation is clean, matches the `python -m password_checker` invocation pattern, and keeps the test surface for the engine independent of the CLI.

---

## Consequences

**Positive:**
- Each rule is independently testable and independently skippable.
- O(1) dictionary lookup via frozenset computed at import.
- `top_feedback()` prioritizes by point deficit — the advice a user receives first is always the most impactful change.
- Grade-based exit codes integrate cleanly with CI scripts.
- Engine/CLI separation allows `run()` to be called without any output side effects.

**Negative / Trade-offs:**
- The common password list is curated, not comprehensive. It contains 100 entries. A real security audit would use a breach corpus of millions of entries (e.g., Have I Been Pwned). The module docstring acknowledges this.
- Entropy is estimated, not measured. `math.log2(pool_size) * length` assumes uniform random character selection. Most human-chosen passwords are not uniformly random — they cluster around keyboard patterns, words, and dates. Shannon entropy would overestimate real-world guessability for most human passwords.
- The leet-speak map covers the most common 8 substitutions. Novel substitutions (`!` for `i`, `€` for `e`) are not covered.

---

*Constitution reference: Articles 1, 2, 3. Amendment 3.3: `common_passwords.py` is a static data module exempt from line limit.*


---


# Technical Design Document
## App 06 — Password Checker
**DataGuard Group | Document 2 of 5**

---

## Overview

Password Checker analyzes password strength using seven layered rules and produces scored, graded reports with actionable feedback. It operates in single-password mode (CLI `--password`) or batch mode (file input). The engine is fully separated from the CLI layer.

**Files:** `password_checker.py` (424 lines), `__main__.py` (CLI), `common_passwords.py` (static data, Amendment 3.3), `formatter.py` (shared), `errors.py` (shared)
**Entry points:** `run()` (public API), `python -m password_checker` (CLI via `__main__.py`)
**Dependencies:** `math`, `re`, `string` (stdlib); `errors`, `common_passwords`, `formatter` (DataGuard)

---

## Data Flow

```
Input (str or single_password config key)
        │
        ▼
run(input_text, config)
        │
        ├─ single_password → [password]
        └─ splitlines()   → [passwords]
        │
        ▼
[analyze_password(pw, config) for pw in passwords]
        │
        ├─ check_length()
        ├─ check_diversity()
        ├─ check_dictionary()   ← normalized_password() + COMMON_PASSWORDS_LOWER
        ├─ check_sequences()    ← detect_sequences()
        ├─ check_repeats()
        ├─ check_keyboard_patterns()  ← detect_keyboard_patterns()
        └─ calculate_entropy()  ← character_pool_size()
        │
        ▼
score = sum(rule["points"])
grade = grade_from_score(score)
feedback = top_feedback(rules)
        │
        ├─ len == 0 → "No passwords to analyze."
        ├─ len == 1 → render_single_analysis()
        └─ len > 1  → render_batch_analysis() via format_table()
        │
        ▼
Standard DataGuard result dict + "analyses" key
```

---

## Module-Level Constants

### `COMMON_PASSWORDS_LOWER`
`frozenset[str]` — All 100 entries from `common_passwords.COMMON_PASSWORDS` lowercased. Computed once at import. O(1) membership testing.

### `KEYBOARD_ROWS`
`list[str]` — Four keyboard rows: `"1234567890"`, `"qwertyuiop"`, `"asdfghjkl"`, `"zxcvbnm"`. Used by `detect_keyboard_patterns()` to check forward and reverse keyboard walks.

### `LEET_MAP`
`str.maketrans` mapping — 8 common leet substitutions: `@ → a`, `4 → a`, `3 → e`, `1 → i`, `0 → o`, `$ → s`, `5 → s`, `7 → t`. Applied in `normalized_password()`.

### `GRADE_BANDS`
`list[tuple[int, str]]` — Score thresholds in descending order:

| Minimum Score | Grade |
|---|---|
| 85 | Fortress |
| 70 | Strong |
| 50 | Fair |
| 30 | Weak |
| 0 | Terrible |

---

## Rule Reference

All rule functions return a dict conforming to:
```python
{
    "name": str,
    "points": int,
    "max_points": int,
    "passed": bool,
    "details": str,
    "feedback": str,
}
```

### `check_length(password, min_length) → dict`
Max 20 points.
- `length >= 20` → 20 points
- `length >= min_length` → `12 + (length - min_length) * 1.0` (capped at 20)
- `length < min_length` → `(length / min_length) * 12` (scaled, floor 0)

Passed when `len(password) >= min_length`.

---

### `check_diversity(password) → dict`
Max 20 points. 5 points per character class present:
- lowercase `[a-z]`
- uppercase `[A-Z]`
- digits `\d`
- symbols (from `string.punctuation`)

Passed when 3 or more classes present.

---

### `check_dictionary(password) → dict`
Max 20 points. Returns 20 if not in dictionary, 0 if found.

Checks two forms:
1. `password.lower()` against `COMMON_PASSWORDS_LOWER`
2. `normalized_password(password)` (leet-normalized) against `COMMON_PASSWORDS_LOWER`

Passed when neither form matches.

---

### `detect_sequences(password) → list[str]`
Sliding 3-character window over lowercased password. Returns all 3-char substrings where consecutive ordinal differences are `[1, 1]` (ascending: `abc`, `123`) or `[-1, -1]` (descending: `cba`, `321`).

### `check_sequences(password) → dict`
Max 10 points. 10 if no sequences found, 0 otherwise.

---

### `check_repeats(password) → dict`
Max 5 points. Uses `re.search(r"(.)\1{2,}", password)` — finds 3+ consecutive identical characters. 5 if none found, 0 if found.

---

### `detect_keyboard_patterns(password) → list[str]`
For each keyboard row and each window size 3–5 (capped at row length): checks whether the window or its reverse appears in `password.lower()`. Returns all matches.

### `check_keyboard_patterns(password) → dict`
Max 10 points. 10 if no patterns found, 0 otherwise.

---

### `character_pool_size(password) → int`
Returns the sum of character class sizes present:
- Lowercase present → +26
- Uppercase present → +26
- Digits present → +10
- Symbols present → +`len(string.punctuation)` (32)

Minimum 1.

### `calculate_entropy(password) → dict`
Max 15 points. Formula: `entropy_bits = len(password) * log2(character_pool_size(password))`

| Entropy bits | Points | Label |
|---|---|---|
| ≥ 80 | 15 | Excellent |
| ≥ 60 | 12 | Strong |
| ≥ 40 | 8 | Moderate |
| < 40 | 3 | Low |

Passed when `entropy_bits >= 40`. Adds `entropy_bits` key to the result dict.

---

### Score Summary

| Rule | Max Points |
|---|---|
| length | 20 |
| diversity | 20 |
| dictionary | 20 |
| sequences | 10 |
| repeats | 5 |
| keyboard_patterns | 10 |
| entropy | 15 |
| **Total** | **100** |

---

## Additional Functions

### `mask_password(password, show_password) → str`
- `show_password=True` → returns plain password
- `len == 0` → `"<empty>"`
- `len <= 2` → `"**"` (all masked)
- Otherwise → first + `*`×(n-2) + last

### `normalized_password(password) → str`
`password.lower().translate(LEET_MAP)` — lowercases and applies leet substitutions.

### `grade_from_score(score) → str`
Iterates `GRADE_BANDS`, returns first label where `score >= threshold`.

### `top_feedback(rule_results) → list[str]`
Filters failed rules, sorts descending by `max_points - points` (biggest deficit first), returns up to 3 `feedback` strings.

### `analyze_password(password, config) → dict`
Validates `min_length` (raises `ParseError` if not int, `ValidationError` if < 1). Runs all rules. Returns:
```python
{
    "password": str,
    "score": int,
    "grade": str,
    "rules": list[dict],
    "feedback": list[str],
    "entropy_bits": float | None,
}
```

---

## Stats Schema

```python
{
    "passwords_analyzed": int,
    "average_score": float,
    "weakest_line": int | str,   # 1-based line number, or "" if no passwords
    "below_fair": int,
}
```


---


# Interface Design Specification
## App 06 — Password Checker
**DataGuard Group | Document 3 of 5**

---

## Public API

### Primary Entry Point

```python
run(input_text: str, config: dict | None = None) -> dict
```

**Config keys:**

| Key | Type | Default | Description |
|---|---|---|---|
| `single_password` | `str \| None` | `None` | Analyze one password (bypasses `input_text`) |
| `min_length` | `int` | `8` | Minimum length for scoring |
| `no_dictionary` | `bool` | `False` | Skip dictionary check |
| `no_entropy` | `bool` | `False` | Skip entropy calculation |
| `show_password` | `bool` | `False` | Show real passwords in output |
| `source_name` | `str` | `"<input>"` | Label for metadata |

---

### CLI

```bash
# Single password analysis
python -m password_checker --password "myPassword123!"

# Show real password in output
python -m password_checker --password "myPassword123!" --show

# Custom minimum length
python -m password_checker --password "abc123" --min-length 12

# Skip dictionary check
python -m password_checker --password "password" --no-dictionary

# Skip entropy calculation
python -m password_checker --password "abc" --no-entropy

# Batch file analysis
python -m password_checker --file passwords.txt

# Export JSON report
python -m password_checker --password "abc" --export report.json

# Custom source label
python -m password_checker --file audit.txt --source-name "Q4 audit"
```

**Exit codes:**
- `0` — All passwords graded Fair or better
- `1` — At least one password graded Weak or Terrible
- `2` — Argument error (`ValidationError` or `InputError`)

---

## Result Envelope

```python
{
    "module_name": "audit",
    "title": "DataGuard Password Audit Report",
    "output": str,          # Single: detailed report; batch: table
    "analyses": list[dict], # One analysis dict per password
    "findings": list[dict], # Weak/Terrible passwords as findings
    "warnings": list[str],  # Empty or ["N password(s) scored Weak or Terrible."]
    "errors": [],
    "stats": dict,
    "metadata": {"source": str, "minimum_length": int},
    "summary": str,
}
```

---

## Analysis Schema

Each item in `result["analyses"]`:
```python
{
    "password": str,            # Raw password (not masked)
    "score": int,               # 0–100
    "grade": str,               # "Terrible" | "Weak" | "Fair" | "Strong" | "Fortress"
    "rules": list[dict],        # One per rule
    "feedback": list[str],      # Top 3 actionable suggestions
    "entropy_bits": float | None,
}
```

---

## Input/Output Examples

### Single strong password
```
Password: x***P1z
Score: 92/100
Grade: Fortress
Entropy: 158.4 bits

Rule checks:
- length: PASS (20/20)
  Length is 30; minimum target is 8.
- diversity: PASS (20/20)
  Uses 4 character classes.
- dictionary: PASS (20/20)
  Compared against the built-in common-password dictionary.
- sequences: PASS (10/10)
  No ascending or descending 3-character sequences found.
- repeats: PASS (5/5)
  No repeated 3-character streaks found.
- keyboard_patterns: PASS (10/10)
  No obvious keyboard walks found.
- entropy: PASS (15/15)
  Estimated entropy is 158.4 bits (Excellent).
```

### Single weak password
```
Password: p*****d
Score: 20/100
Grade: Terrible
Entropy: 37.6 bits

Rule checks:
- length: FAIL (8/20)  ...
- dictionary: FAIL (0/20)  ...

Top advice:
- Choose something less common than a top-list password.
- Add uppercase, digits.
- Increase length and character variety to raise entropy.
```

### Batch file output (table)
```
Password    Score  Grade     Top issue
----------  -----  --------  ---------
p*****d     20     Terrible  Choose something less common...
x***P1z     92     Fortress  Looks healthy.
a*c         15     Terrible  Add at least 5 more characters.
```

### Empty file
```
No passwords to analyze.
```

---

## Finding Schema (Weak/Terrible passwords)

```python
{
    "severity": "medium",
    "category": "weak_password",
    "line": int,    # 1-based index in analyses list
    "message": str, # "Password at line N scored X (Grade)."
}
```

---

## Grade Color Mapping (CLI only)

| Grade | Color |
|---|---|
| Terrible | red |
| Weak | red |
| Fair | yellow |
| Strong | green |
| Fortress | green |

Colors are applied only when stdout is a TTY and `NO_COLOR` is not set.


---


# Runbook
## App 06 — Password Checker
**DataGuard Group | Document 4 of 5**

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — stdlib only
- `errors.py`, `formatter.py`, and `common_passwords.py` must be in the same directory or on `PYTHONPATH`

---

## Installation

```bash
git clone https://github.com/PrincetonAfeez/Password-Checker
cd Password-Checker
```

Confirm `errors.py`, `formatter.py`, and `common_passwords.py` are present. No `pip install` required.

---

## Running the CLI

### Analyze a single password
```bash
python -m password_checker --password "myPassword123!"
```

### Show the real password in output
```bash
python -m password_checker --password "myPassword123!" --show
```

### Custom minimum length requirement
```bash
python -m password_checker --password "abc123" --min-length 12
```

### Skip dictionary check (useful for system-generated keys)
```bash
python -m password_checker --password "qwerty" --no-dictionary
```

### Batch analysis from file (one password per line)
```bash
python -m password_checker --file passwords.txt
```

### Export full JSON report
```bash
python -m password_checker --file passwords.txt --export report.json
```

### Use in CI/CD pipeline (non-zero exit if any password fails)
```bash
python -m password_checker --file passwords.txt
echo "Exit: $?"   # 0 = all fair+, 1 = at least one weak/terrible
```

---

## Using as a Library

### Analyze a single password
```python
from password_checker import run

result = run("", {"single_password": "myPassword123!", "min_length": 10})
analysis = result["analyses"][0]
print(f"Grade: {analysis['grade']}")
print(f"Score: {analysis['score']}/100")
print(f"Feedback: {analysis['feedback']}")
```

### Batch analysis from text
```python
passwords_text = "password\nabc123\nxK9#mQ2$vL5nR8wP1z\n"
result = run(passwords_text, {"min_length": 8})
for analysis in result["analyses"]:
    print(f"{analysis['grade']:10} {analysis['score']:3}/100")
```

### Analyze without dictionary check
```python
result = run("", {"single_password": "qwerty", "no_dictionary": True})
# Dictionary rule will show "skipped" in details
```

### Inspect rule-level results
```python
from password_checker import analyze_password

analysis = analyze_password("P@ssw0rd", {})
for rule in analysis["rules"]:
    status = "✓" if rule["passed"] else "✗"
    print(f"{status} {rule['name']:20} {rule['points']:2}/{rule['max_points']:2}")
```

### Check exit code logic manually
```python
from password_checker import run

result = run("password\nxK9#mQ2$vL5nR8wP1z\n")
weak_count = result["stats"]["below_fair"]
print(f"Passwords below Fair: {weak_count}")
```

---

## Running Tests

```bash
pip install pytest
pytest test_password_checker.py test_cli_subprocess.py test_formatter_output.py -v
```

### Specific test groups
```bash
pytest test_password_checker.py -v -k "dictionary"
pytest test_password_checker.py -v -k "entropy"
pytest test_password_checker.py -v -k "grade"
pytest test_cli_subprocess.py -v
```

---

## Troubleshooting

### Exit code 2 with `--min-length 0`
`--min-length` must be at least 1. Values of 0 or below trigger a `ValidationError`.

### All passwords pass dictionary check despite being common
Verify that `common_passwords.py` is importable. The check uses `COMMON_PASSWORDS_LOWER`, which is built at import time. If the module is not found, the check will raise `ModuleNotFoundError` before any analysis runs.

### Leet-speak variant not being caught
The current `LEET_MAP` covers 8 substitutions (`@→a`, `4→a`, `3→e`, `1→i`, `0→o`, `$→s`, `5→s`, `7→t`). Novel substitutions (`!→i`, `€→e`) are not in the map. Add custom substitutions to `LEET_MAP` if needed for specific auditing contexts.

### Entropy seems higher than expected
The entropy formula assumes uniform random selection from the detected character pool. Human-chosen passwords cluster around common patterns, making their effective entropy lower than the mathematical estimate. The score is an upper bound on randomness, not a measure of actual guessability.

### Batch file produces no output
Check that the file contains at least one non-empty line. Blank lines are skipped. Files with only whitespace lines produce `"No passwords to analyze."`.


---


# Lessons Learned
## App 06 — Password Checker
**DataGuard Group | Document 5 of 5**

---

## Why This Design Was Chosen

The layered rule architecture was chosen because it maps directly to how password strength is actually evaluated — not as a single holistic score, but as the absence of multiple specific failure modes. A password can be long but common (fails dictionary), complex but predictable (fails keyboard patterns), or have good entropy but contain a repeated character run. Each failure mode is orthogonal to the others, so each deserves its own check, its own score contribution, and its own feedback message.

The `top_feedback()` priority order — sort by point deficit, not by rule index — came from thinking about what makes feedback actionable. A password that fails the dictionary check (0/20, deficit 20) should get that advice first, not length advice that has a smaller deficit. The sort by deficit ensures the user's first action has the highest potential impact on their score.

---

## What Was Intentionally Omitted

**Have I Been Pwned integration:** The module uses a local list of 100 common passwords. A real security audit would query the HIBP k-anonymity API or a local breach corpus to check against billions of known compromised passwords. This was intentionally omitted because the DataGuard group is designed to be stdlib-only and offline. The module docstring acknowledges the limitation explicitly.

**Zxcvbn-style pattern matching:** The `zxcvbn` library (Dropbox's password strength estimator) uses a comprehensive pattern matching approach that covers dates, names, spatial patterns, and dictionary variation much more thoroughly than this module. It was intentionally excluded to avoid a third-party dependency and to build the pattern matching understanding from scratch.

**Unicode password support:** The entropy calculation and character pool sizing work for ASCII passwords. Unicode passwords (emoji, CJK characters) would have larger pool sizes and higher theoretical entropy, but the current pool calculation would incorrectly classify them as symbols or miss them entirely.

**Configurable rule weights:** All rule weights are hardcoded. A `config["rule_weights"]` option that lets callers override the max_points for each rule would make the checker more adaptable for different security policies (e.g., a financial institution that wants length to count for 40 points instead of 20).

---

## Biggest Weakness

The entropy estimation assumes uniform random selection:
```python
entropy_bits = len(password) * math.log2(pool_size)
```

This is mathematically correct for random passwords but overestimates the real guessability of human-chosen passwords. `Summer2024!` uses digits, uppercase, lowercase, and symbols — the pool calculation gives it ~160 bits of entropy — but it would be cracked quickly by any dictionary attack that includes date suffixes and season words. The module scores it higher than it should because it passes the diversity check and the simplified entropy calculation.

A proper guessability estimator would measure the entropy of the *specific pattern* used (word + year + symbol), not just the character pool. This requires a much more complex model than this scope allows.

---

## Scaling Considerations

**If the common password list needs to grow:** `common_passwords.py` is a static data module — adding entries requires only appending to `COMMON_PASSWORDS`. The `frozenset` is rebuilt at import. For a list of millions of entries, a binary file or a bloom filter would be more memory-efficient than a frozenset.

**If batch files grow to millions of passwords:** The current implementation calls `analyze_password()` for each password and accumulates all results in memory. A streaming implementation that analyzes and outputs one row at a time without accumulating would handle large files with constant memory.

**If international leet-speak is needed:** The `LEET_MAP` is a `str.maketrans` dict — adding entries is a one-line change. A comprehensive leet-speak normalizer for multiple languages and extended Unicode substitutions would be a separate module.

---

## What the Next Refactor Would Be

1. **Configurable rule weights** — `config["rule_weights"]` dict to allow policy-specific scoring.
2. **Streaming batch output** — write each row as it is analyzed rather than accumulating.
3. **Extended leet-speak map** — cover additional common substitutions beyond the current 8.
4. **Unicode character pool** — correctly size the pool for non-ASCII character sets.
5. **HIBP k-anonymity check** — optional network-based check against the breach corpus.

---

## What This Project Taught

**O(1) is a design decision, not an optimization.** Moving from `if password.lower() in [entry.lower() for entry in COMMON_PASSWORDS]` (O(n) on every call) to `frozenset` at import time is not an optimization detail — it is an architectural choice about where work happens. The frozenset version puts the work at import time, once. The list version puts it at analysis time, on every call. Recognizing this distinction early, before performance is a problem, is a system design skill.

**Feedback priority is a design problem.** The first version of `top_feedback()` returned feedback in rule order — length first, then diversity, etc. This produced useless output for a strong-length, weak-dictionary password (the first advice was "Good length coverage." — not actionable). Sorting by deficit made the function genuinely useful. A function that produces correct but unhelpful output is an incomplete design.

**Engine/CLI separation enables library use without surprises.** The bootstrapper (App 07) imports `password_checker.run` directly. Having argparse, sys.stdout.write, or sys.exit() in `password_checker.py` would make that import produce side effects. The clean separation into `password_checker.py` (engine) and `__main__.py` (CLI) means the engine can be imported, tested, and called without any CLI infrastructure.

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation) for App 06.*
