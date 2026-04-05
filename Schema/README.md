# Schema folder for `princetonafeezx/Password-Checker`

This package adds a `Schema/` directory for the repository's real structured data model.

Included schemas:
- `config.schema.json` — runtime config accepted by `password_checker.run()`
- `rule-result.schema.json` — one rule result object
- `analysis.schema.json` — output of `analyze_password()`
- `finding.schema.json` — weak-password finding objects from `run()`
- `stats.schema.json` — aggregate report stats
- `metadata.schema.json` — report metadata block
- `report.schema.json` — full JSON export shape produced by `formatter.render_report(..., report_format="json")`
- `shared.schema.json` — shared enums and helper definitions

Placement:
Copy this whole `Schema/` folder into the repository root.

Notes:
- Schemas target JSON Schema Draft 2020-12.
- `report.schema.json` is the top-level schema to validate exported JSON reports.
- `analysis.schema.json` is the top-level schema to validate a single `analyze_password()` result.
- The schemas were derived directly from the repository's source files:
  `password_checker.py`, `formatter.py`, `__main__.py`, and `errors.py`.
