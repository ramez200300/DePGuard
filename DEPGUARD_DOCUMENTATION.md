# DePGuard — Complete Project Documentation & Work Log

> Living document for the graduation project. It describes the current state of the
> repository, every module, the database, the scoring model, and every change made
> during maintenance sessions, together with how each change was verified.
>
> Last updated: 2026-11-21 · Python 3.14.7 (project rule: 3.9+) · 20 tests passing.

---

## 1. Project Overview

**DePGuard** is an integrated web vulnerability and dependency scanner that combines
two security techniques in one small tool:

1. **DAST (URL scan)** — checks a web target for missing security headers, insecure
   cookies, TLS/certificate problems, and commonly exposed paths
   (`/.git/HEAD`, `/.env`, `/robots.txt`, `/admin`).
2. **SCA (manifest scan)** — parses `requirements.txt` or `package.json`, queries the
   **OSV.dev API** for known vulnerabilities, classifies them by severity, and writes a
   JSON **SBOM** (Software Bill of Materials).

Every scan is stored in a local **SQLite** database with a single aggregated
**risk score** and **risk level**. Results can be reviewed in a **Flask** dashboard or
exported as a **PDF** report. A **Typer** CLI exposes the same functionality.

The tool is intentionally local-only and non-authenticated: it is a Bachelor's
graduation project, not a production SaaS.

---

## 2. Current Status at a Glance

- **Tests:** 20 `unittest` tests, all passing (`Ran 20 tests ... OK`).
- **Source size:** 826 lines of Python across 6 modules (all files under 200 lines,
  all functions under 30 lines).
- **Interfaces:** 3 CLI commands + 5 Flask routes.
- **Data:** SQLite database with 4 tables and automatic schema migration.
- **Outputs:** PDF reports (`output/report_<id>.pdf`) and timestamped SBOM files
  (`output/sbom_<manifest>_<timestamp>.json`).
- **Not verified:** Docker image build (Docker is not installed on the machine) and a
  visual browser pass over the dashboard after the latest template changes.

Module line counts:

- `src/sca.py` — 198
- `src/db.py` — 176
- `src/scanner.py` — 173
- `src/app.py` — 111
- `src/cli.py` — 84
- `src/report.py` — 84

Templates: `home.html` 63, `new_scan.html` 38, `scan_details.html` 47.

---

## 3. Technology Stack

- **Language:** Python 3.9+ (standard library preferred), verified on 3.14.7.
- **CLI:** Typer.
- **Web:** Flask (Jinja2 templates, Bootstrap 5 from a CDN).
- **Database:** SQLite through the stdlib `sqlite3` module — no ORM.
- **HTTP:** `requests` (target fetching and OSV API calls).
- **PDF:** fpdf2.
- **External API:** OSV.dev (`https://api.osv.dev/v1/query`).
- **Tests:** stdlib `unittest`.

Dependencies (`requirements.txt`): `typer==0.29.1`, `flask==3.1.3`,
`requests==2.34.2`, `fpdf2==2.9.0`.

Project rules (from `AGENTS.md`): no async/threads, no ORM, no complex patterns,
no dependency without asking, no function over 30 lines, no file over 200 lines,
simple code suitable for a Cybersecurity Bachelor's student, and only build what is
IN scope in `MVP_SCOPE.md` (Docker and Auth are out of MVP).

---

## 4. Project Structure

```text
pro/  (DePGuard)
├── src/
│   ├── app.py              # Flask app, routes, form handling
│   ├── cli.py              # Typer commands: scan-url, scan-manifest, report
│   ├── db.py               # Schema, migration, data access
│   ├── report.py           # PDF generation with fpdf2
│   ├── sca.py              # Manifest parsing, OSV, SBOM, risk scoring
│   ├── scanner.py          # URL/DAST checks
│   └── templates/
│       ├── home.html           # Scan list with risk badges
│       ├── new_scan.html       # URL + manifest form
│       └── scan_details.html   # Findings and download buttons
├── data/
│   └── depguard.db         # SQLite database, created at runtime
├── output/                 # Generated PDF reports and SBOM files
├── tests/
│   ├── test_app.py         # 7 tests: routes, 404s, SBOM download
│   ├── test_db.py          # 6 tests: schema, saving, migration
│   ├── test_sca.py         # 3 tests: parsing, empty manifest, split
│   └── test_scanner.py     # 4 tests: URL cleaning, header checks
├── samples/
│   ├── vulnerable_requirements.txt
│   └── vulnerable_package.json
├── requirements.txt
├── README.md
└── DEPGUARD_DOCUMENTATION.md   # this file
```

All paths are computed from `__file__`, so the application works regardless of the
current working directory:

- `db.DB_PATH` → `<project>/data/depguard.db`
- `sca.OUTPUT_DIR` and `report.OUTPUT_DIR` → `<project>/output`

---

## 5. Architecture and Data Flow

### 5.1 URL scan

```text
input (CLI argument or web form)
  -> permission confirmation (prompt / checkbox)
  -> scanner.clean_url(url)
  -> scanner.scan(url)
       fetch()          HTTP GET with raise_for_status()
       check_headers()  four security headers
       check_cookies()  Secure / HttpOnly flags
       check_tls()      TLS version + certificate expiry
       check_paths()    exposed paths with false-positive guards
  -> findings list
  -> sca.calculate_risk_score(findings) -> (score, level)
  -> db.save_scan("url", "url", url, findings, risk_score, risk_level)
  -> CLI prints "Overall risk: ..." / web redirects to /scan/<id>
```

### 5.2 Manifest scan

```text
path (requirements.txt | package.json)
  -> sca.parse_manifest(path)     empty file -> ValueError
  -> sca.scan_manifest(path)      one OSV query per package
  -> items: [{name, version, ecosystem, vulns}]
  -> sca.vuln_findings(items)     flattened, de-duplicated findings
  -> sca.calculate_risk_score(findings)
  -> sca.save_sbom(items, manifest) -> output/sbom_<name>_<timestamp>.json
  -> db.save_scan("manifest", "sca", value, findings, sbom_path, score, level)
```

### 5.3 PDF report

```text
scan_id
  -> db.get_scan(scan_id) + db.list_vulnerabilities(scan_id)
  -> header: metadata, severity counts, overall risk score (fallback recalculation
     for old scans that stored NULL)
  -> one block per finding, with a page-break guard so a title never separates
     from its description
  -> output/report_<id>.pdf, recorded in the reports table
```

### 5.4 Dashboard

```text
GET  /              -> home.html        (all scans, newest first, risk badge)
GET  /new           -> new_scan.html    (URL or manifest, permission checkbox)
POST /new           -> runs the scan and redirects to /scan/<id>
GET  /scan/<id>     -> scan_details.html or 404
GET  /report/<id>   -> PDF download or 404
GET  /sbom/<id>     -> SBOM download, 404 when path is missing / file gone
```

---

## 6. Module Reference

### 6.1 `src/scanner.py` (DAST)

Constants:

- `SECURITY_HEADERS` — four headers, each with a plain-English explanation.
- `PATHS` — `/.git/HEAD`, `/.env`, `/robots.txt`, `/admin`.
- `SEVERITY` — severity per finding key (`.env` is Critical, `.git/HEAD`, old TLS,
  and TLS errors are High, the rest Medium/Low).

Functions:

- `clean_url(url)` — prefixes `https://` when no scheme is present.
- `fetch(url)` — GET with a 10-second timeout and `raise_for_status()`.
- `check_headers(headers)` — one Medium/Low finding per missing header.
- `check_cookies(response)` — parses raw `Set-Cookie` lines and flags missing
  `Secure` / `HttpOnly` attributes.
- `expiry_finding(cert)` — expired certificate, or expiring within 30 days.
- `check_tls(url)` — TLS handshake with the CA bundle from `requests.certs`;
  reports protocol version and expiry; returns `(findings, info_string)`.
- `random_path_length(url)` — baseline length of a random 404 page.
- `login_page(response)` — detects a real password field in the HTML.
- `admin_exposed(response, random_length)` — length-difference + content-type +
  login-page heuristic.
- `check_paths(url)` — probes each path without following redirects; skips HTML
  responses (except `/admin`), validates that `.git/HEAD` really starts with `ref:`.
- `scan(url)` — orchestrates all checks; a failed fetch becomes a clean `ValueError`.

### 6.2 `src/sca.py` (SCA + scoring)

Constants: `OSV_URL`, `OUTPUT_DIR`, `SEVERITY_MAP`
(LOW/MODERATE/HIGH/CRITICAL → Low/Medium/High/Critical), `RISK_WEIGHTS`.

Functions:

- `split_requirement(text)` — drops environment markers, splits at the first
  comparison operator, strips extras such as `pkg[extra]`.
- `parse_requirements(path)` — skips blanks, comments, `-` lines, and entries with no
  usable numeric version (and prints a "Skipped" line).
- `parse_package_json(path)` — reads `dependencies` and `devDependencies`, strips
  range prefixes (`^ ~ > < =`).
- `parse_manifest(path)` — empty file raises `ValueError("Manifest file is empty or
  invalid")`; otherwise dispatches by filename, with JSON errors normalized.
- `ecosystem(path)` — `npm` for `package.json`, otherwise `PyPI`.
- `query_osv(name, version, eco)` — POST to OSV; returns the `vulns` list.
- `scan_manifest(path)` — parses, validates that at least one package was found, then
  queries OSV per package. A request failure prints a clear message and raises, so a
  broken API call is never mistaken for "no vulnerabilities".
- `vuln_severity(vuln)` — from `database_specific.severity`, default Medium.
- `vuln_title(vuln, name, version)` — prefers the CVE alias over the OSV id.
- `vuln_description(vuln)` — summary plus CVSS vectors, each truncated to 50
  characters, CVSS v4 ignored (the documented field is a v3-style score).
- `vuln_findings(items)` — flattens items into findings and removes duplicates by
  title.
- `save_sbom(items, manifest)` — writes a timestamped, per-run JSON file to
  `output/`, never overwriting earlier SBOMs.
- `risk_classification(score)` — limit table that maps a score to its level.
- `calculate_risk_score(findings)` — weighted sum, returns `(score, level)`.

### 6.3 `src/db.py`

Constants: `DB_PATH`, `SCHEMA`, `SCAN_COLUMNS`
(`sbom_path TEXT`, `risk_score INTEGER`, `risk_level TEXT`).

Functions:

- `connect()` — creates the data folder, sets `row_factory`, enables foreign keys.
- `scan_column_names(conn)` — reads `PRAGMA table_info(scans)`.
- `add_missing_columns(conn)` — adds each missing column with `ALTER TABLE`; a
  duplicate-column `OperationalError` is tolerated only when the column now exists,
  which makes the migration safe to run repeatedly.
- `init_db()` — executes the schema and applies the migration (idempotent).
- `get_or_create_target(kind, value)` — reuses an existing target row.
- `add_scan(target_id, scan_type, sbom_path=None, risk_score=None, risk_level=None)`.
- `add_vulnerabilities(scan_id, findings)` — one row per finding.
- `save_scan(kind, scan_type, value, findings, sbom_path=None, risk_score=None,
  risk_level=None)` — convenience wrapper returning the scan id.
- `list_scans()` — joins targets, counts findings per scan, returns risk fields,
  newest first.
- `get_scan(scan_id)` — one scan with `sbom_path`, risk fields, and target value.
- `list_vulnerabilities(scan_id)` — findings ordered by insertion.
- `add_report(scan_id, file_path)` — records each generated report.

### 6.4 `src/cli.py`

- `main()` — Typer callback; runs `db.init_db()` before any command and makes Typer
  treat the app as a command group.
- `scan_url(url)` — permission prompt, scan, print findings, print
  `Overall risk: <level> (score N)`, save, print the scan id.
- `scan_manifest(path)` — scan, print per-package vulnerability counts, save the SBOM,
  print the overall risk, save the scan with the SBOM path.
- `report(scan_id)` — validates the id, exports the PDF, prints its path.

### 6.5 `src/app.py`

- `url_scan(url)` / `manifest_scan(file)` — helpers returning `(scan_id, message)`.
  Manifest uploads are limited to `requirements.txt` and `package.json`, saved to a
  temporary directory, and removed afterwards; the maximum upload size is 1 MiB.
- `home()`, `scan_details(scan_id)`, `download_report(scan_id)`,
  `download_sbom(scan_id)`, `new_scan()`.
- `download_sbom` returns 404 for a missing scan, a missing path, a file that no
  longer exists, or an `OSError` while sending.
- Runs with `app.run(debug=True)` on `http://127.0.0.1:5000`.

### 6.6 `src/report.py`

- `clean(text)` — latin-1 sanitizing for the built-in fpdf fonts.
- `severity_counts(findings)` — Critical/High/Medium/Low counters.
- `finding_height(pdf, finding)` — measures a finding block with
  `multi_cell(..., dry_run=True, output="HEIGHT")`.
- `write_header(pdf, scan, findings, counts)` — title, metadata, counts, and the
  bold `Overall Risk Score: N (Level)` line; recalculates the score for older scans
  stored before scoring existed.
- `export_report(scan_id)` — builds the PDF, guards page breaks, writes
  `output/report_<id>.pdf`, records it, returns the path (or `None`).

### 6.7 Templates

- `home.html` — navbar, table of scans (ID, target, type, date, risk badge, findings
  count), colored risk badges, `N/A` for old scans, empty state with a CTA.
- `new_scan.html` — URL field, manifest upload, permission checkbox, warning alert
  area.
- `scan_details.html` — large risk badge next to the title, back / PDF / SBOM
  buttons, findings list with severity badges, empty state.

---

## 7. Database Schema

```sql
targets(id INTEGER PK, kind TEXT, value TEXT, created_at TEXT)
scans(id INTEGER PK, target_id INTEGER FK, scan_type TEXT,
      sbom_path TEXT, risk_score INTEGER, risk_level TEXT, created_at TEXT)
vulnerabilities(id INTEGER PK, scan_id INTEGER FK, title TEXT,
                severity TEXT, description TEXT)
reports(id INTEGER PK, scan_id INTEGER FK, file_path TEXT, created_at TEXT)
```

- `targets.kind` is `url` or `manifest`; `scans.scan_type` is `url` or `sca`.
- Foreign keys are enabled on every connection.
- `get_or_create_target` prevents duplicate target rows for the same value.
- Older databases created before SBOM support and before risk scoring are upgraded
  in place by `init_db()`; existing rows keep `NULL` in the new columns, which the
  UI shows as `N/A` and the PDF recalculates from stored findings.

---

## 8. Risk Scoring Model

Weights applied per finding:

- Critical = 10
- High = 5
- Medium = 2
- Low = 1

Classification of the total score:

- 0 → **Safe**
- 1–10 → **Low Risk**
- 11–25 → **Medium Risk**
- 26–50 → **High Risk**
- above 50 → **Critical Risk**

`calculate_risk_score(findings)` returns `(total_score, classification)`. Unknown
severities contribute 0. The score is computed once per scan, stored in `scans`, and
reused by the CLI, the dashboard, and the PDF.

Badge colors in the UI: Critical red (`bg-danger`), High yellow (`bg-warning`), Medium
blue (`bg-info`), Low grey (`bg-secondary`), Safe green (`bg-success`).

Worked examples used during verification: no findings → `(0, "Safe")`; one Critical
→ `(10, "Low Risk")`; eleven Low → `(11, "Medium Risk")`; six High →
`(30, "High Risk")`.

---

## 9. Generated Artifacts

- `data/depguard.db` — created on first run; stores targets, scans, findings, reports.
- `output/report_<scan_id>.pdf` — regenerated on each export, one file per scan.
- `output/sbom_<manifest-name>_<YYYYmmdd_HHMMSS_microseconds>.json` — unique per run,
  containing the manifest name, generation time, and each package with its
  vulnerabilities (id + summary).

PDF contents: title, generation timestamp, scan id, type, target, scan date, number of
findings, severity counts, overall risk score with level, then each finding
(severity + title, description).

---

## 10. Work Log — Everything Done in This Project

### Phase 1 — Initial implementation

- Typer CLI with `scan-url`, `scan-manifest`, and `report`.
- Flask dashboard with home, new scan, scan details, and PDF download routes.
- `scanner.py` DAST checks: headers, cookies, TLS, exposed paths.
- `sca.py`: requirements/package.json parsing, OSV queries, SBOM output.
- SQLite storage with targets, scans, vulnerabilities, and reports tables.
- fpdf2 report generation and Bootstrap templates.

### Phase 2 — Restructuring and cleanup

- All runtime paths derived from `__file__` so commands work from any directory.
- Templates moved under `src/templates`; data in `data/`, generated files in `output/`.
- Database connections always closed; foreign keys enabled consistently.
- Removed duplicated/unused code paths and kept every file small and readable.

### Phase 3 — Robustness fixes

- `sca.parse_manifest` rejects empty or malformed manifests with a clear message
  instead of silently returning no packages.
- Duplicate findings removed by title (the same CVE reported by several OSV entries).
- CVSS vectors truncated to keep PDF and dashboard rows readable; CVSS v4 entries
  skipped because the field expects a v3-style vector.
- SBOM filenames made unique with a timestamp, so previous scans are not overwritten.
- OSV failures now stop the scan with an explicit message instead of looking like a
  clean scan.
- `fetch()` calls `raise_for_status()`, so error pages are not scanned as content.
- `.env` detection requires a non-HTML 200 response; `.git/HEAD` must start with
  `ref:`; `/admin` uses a length + content-type + login-page heuristic.

### Phase 4 — SBOM download and UI polish

- Added `GET /sbom/<int:scan_id>` with 404 handling for missing scans, missing
  paths, deleted files, and `OSError` during send.
- `scan_details.html` shows the SBOM button only for dependency scans that have one.
- Reworked templates with Bootstrap cards, tables, badges, and empty states.
- PDF page-break guard: a finding title is never left alone at the bottom of a page.

### Phase 5 — Automated tests and samples

- Added a `tests/` package with 20 `unittest` tests (routes, 404s, SBOM download,
  schema creation, save/list/get, migration, manifest parsing, URL helpers).
- Added `samples/vulnerable_requirements.txt` and `samples/vulnerable_package.json`
  for safe demonstration scans.
- `tests/test_app.py` isolates `db.DB_PATH` before importing the app so the real
  database is never touched by tests.

### Phase 6 — Risk scoring

- Added `RISK_WEIGHTS`, `risk_classification`, and `calculate_risk_score` in `sca.py`.
- Added `risk_score` and `risk_level` to the `scans` table plus an idempotent
  `ALTER TABLE` migration for existing databases.
- `add_scan` and `save_scan` accept and store the score; `get_scan` and `list_scans`
  return it.
- CLI prints `Overall risk: <level> (score N)` for both scan commands.
- Dashboard computes and stores the score for both scan types.
- PDF header prints the overall score, recalculating it for pre-scoring scans.
- Home and details templates show colored risk badges, with `N/A` for old scans.

### Phase 7 — Presentation materials

- Rewrote `README.md` with eight sections: description, features, tech stack,
  installation, CLI usage, dashboard usage, tests, and project structure.
- Rewrote this document to reflect the current code, the full work log, and the
  verification results.

---

## 11. Testing and Verification

Run the suite:

```cmd
python -m unittest discover -s tests
```

Add `-v` for a per-test listing. Latest run: `Ran 20 tests in 1.682s — OK`
(exit code 0).

Coverage:

- **`test_app.py` (7):** home 200, new-scan form 200, unknown scan 404, SBOM download
  returns the file with an attachment header, missing file 404, scan without SBOM
  path 404, SBOM button only on dependency scans.
- **`test_db.py` (6):** tables created, saved scan returns a positive id, scan appears
  in `list_scans`, `get_scan` returns the target, migration adds `sbom_path` and is
  safe to run twice, `save_scan` stores the SBOM path.
- **`test_sca.py` (3):** requirements parsing, empty manifest raises `ValueError`,
  requirement splitting.
- **`test_scanner.py` (4):** URL normalization with and without a scheme, missing
  headers in order with expected severities, complete headers produce no findings.

Additional manual verification performed during the risk-scoring work:

- Real database upgraded in place; old scans kept `NULL` risk values as intended.
- Temporary test database: home page rendered the `Low Risk` badge with `Score 10`
  and the details page rendered the same value.
- Generated PDF decompressed and searched: the `Overall Risk Score` line is actually
  present in the file content.
- Score table checked against the requested weights and classification boundaries.

Not verified: the Docker image (Docker is not installed) and a visual browser review
of the dashboard after the last template edits.

---

## 12. Known Limitations

- The dashboard has no authentication, CSRF token, or rate limiting; it is meant for
  local use only (`debug=True`, `127.0.0.1`).
- Findings depend on OSV data quality; packages without a resolvable version are
  skipped during parsing.
- The `/admin` detection is heuristic (200-char length threshold, password-field
  check) and can produce false positives or negatives.
- The PDF uses built-in fpdf fonts, so non-latin-1 characters are replaced by `clean()`.
- Each report export inserts a new row in `reports`, so repeated exports leave
  duplicate history entries.
- Docker is present in the repository but untested; Docker is out of MVP scope.

---

## 13. How to Run

```cmd
:: install
pip install -r requirements.txt

:: URL scan
python src/cli.py scan-url https://example.com

:: dependency scan
python src/cli.py scan-manifest samples/vulnerable_requirements.txt

:: PDF report for scan 1
python src/cli.py report 1

:: dashboard
python src/app.py
:: open http://127.0.0.1:5000

:: tests
python -m unittest discover -s tests
```

Note: `flask --app src.app` from the project root fails with
`ModuleNotFoundError: No module named 'db'` because the modules import each other as
top-level modules. Run `python src/app.py` instead; any external script must set
`PYTHONPATH=src` (or insert `src` into `sys.path`, as the tests do).

---

## 14. Possible Next Steps

- Add unit tests for `calculate_risk_score` and `risk_classification` boundaries.
- Include the risk score in the SBOM file and in the CLI summary of skipped packages.
- Add pagination or filtering to the dashboard scan list.
- Add a custom font so Arabic text survives in the PDF.

---

*End of documentation.*
