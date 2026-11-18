# DePGuard — Full Project Documentation

> Read-only documentation file. No source code was changed to produce it.
> Generated from the current state of the repository (read-only review).

---

## 1. Project Overview

**DePGuard** is a small "DAST-lite" security tool with two capabilities:

1. **URL scan** — checks a web target for missing security headers, insecure cookies,
   TLS/certificate issues, and exposed sensitive paths (`.git/HEAD`, `.env`, `robots.txt`, `/admin`).
2. **Manifest / dependency scan (SCA)** — parses `requirements.txt` or `package.json`,
   queries the OSV.dev API for known vulnerabilities, and generates an SBOM JSON file.

Results are stored in a local **SQLite** database and can be viewed in a **Flask**
dashboard or exported as a **PDF** report.

There is also a command-line interface built with **Typer**.

---

## 2. Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.9-compatible (project rule); observed env Python 3.14.7 |
| CLI | Typer |
| Web framework | Flask |
| HTTP client | requests |
| PDF generation | fpdf2 |
| Database | SQLite (stdlib `sqlite3`) |
| Templates | Jinja2 (via Flask) + Bootstrap 5 (CDN) |
| Container | Docker (python:3.12-slim) |

Dependencies (`requirements.txt`):
- `typer`
- `flask`
- `requests`
- `fpdf2`

No ORM, no async, no classes beyond FPDF usage.

---

## 3. Project Structure / File Map

```
pro/
├── src/
│   ├── cli.py            # Typer CLI: scan-url, scan-manifest, report
│   ├── app.py            # Flask dashboard (4 routes)
│   ├── scanner.py        # URL scanning logic
│   ├── sca.py            # Manifest parsing + OSV + SBOM
│   ├── db.py             # SQLite schema + queries
│   ├── report.py         # PDF report generation
│   └── templates/
│       ├── home.html          # list of scans
│       ├── new_scan.html      # new scan form
│       └── scan_details.html  # single scan findings
├── data/                 # SQLite DB (not opened per rules) -> data/depguard.db
├── output/               # SBOM + PDF reports (not opened per rules)
├── requirements.txt
├── README.md
├── Dockerfile
├── .gitignore
└── DEPGUARD_DOCUMENTATION.md   # this file
```

External (outside project, not modified):
- `C:\Users\ramez\Desktop\DePGuard-docs\WORKLOG.md` (work log, read as attachment)

---

## 4. Architecture & Data Flow

### 4.1 URL scan flow
```
user input (CLI or web form)
  -> permission confirmation
  -> scanner.clean_url(url)
  -> scanner.scan(url)
       -> fetch()            (requests.get)
       -> check_headers()    (missing security headers)
       -> check_cookies()    (Secure / HttpOnly flags)
       -> check_tls()        (TLS version, cert expiry)
       -> check_paths()      (exposed paths)
  -> findings list
  -> db.save_scan("url", "url", url, findings)
  -> print "Saved scan <id>"  (CLI)
     or redirect to /scan/<id> (web)
```

### 4.2 Manifest scan flow
```
path (requirements.txt | package.json)
  -> sca.parse_manifest(path)   (parse_requirements or parse_package_json)
  -> sca.scan_manifest(path)    (query OSV per package)
  -> items (name, version, ecosystem, vulns)
  -> sca.save_sbom(items, path) -> output/sbom.json (overwritten each run)
  -> sca.vuln_findings(items)   -> findings list
  -> db.save_scan("manifest", "sca", path/name, findings)
```

### 4.3 Report flow
```
scan_id
  -> report.export_report(scan_id)
       -> db.get_scan(scan_id), db.list_vulnerabilities(scan_id)
       -> build PDF (fpdf2)
       -> output/report_<id>.pdf
       -> db.add_report(scan_id, basename)
  -> path (CLI prints it) / send_file (web)
```

### 4.4 Dashboard flow (Flask)
```
GET  /           -> home.html (list_scans)
GET  /new        -> new_scan.html
POST /new        -> url_scan() or manifest_scan() -> redirect /scan/<id>
GET  /scan/<id>  -> scan_details.html
GET  /report/<id>-> download_report() -> send_file PDF
```

---

## 5. Module Reference — Every Function

### 5.1 `src/cli.py`
Typer application with an empty callback and 3 commands.

- `app = typer.Typer()` — the CLI app object.
- `@app.callback() def main()` — runs before any command; calls `db.init_db()` to create tables. Makes Typer treat the app as a group of subcommands.
- `@app.command() def scan_url(url)`:
  - Prompts for ownership/permission; cancels if not `y`/`yes`.
  - `scanner.clean_url`, `scanner.scan`; handles exceptions.
  - Prints TLS info + findings; saves scan; prints "Saved scan <id>".
- `@app.command() def scan_manifest(path)`:
  - `sca.scan_manifest(path)`; prints per-package vuln counts.
  - `sca.save_sbom(items, path)`; saves scan; prints "Saved scan <id>".
- `@app.command() def report(scan_id)`:
  - Validates integer; `report.export_report`; prints "Report saved to <path>" or "Scan not found."
- `if __name__ == "__main__": app()` — entry point.

Commands usage:
```
python src/cli.py scan-url https://example.com
python src/cli.py scan-manifest requirements.txt
python src/cli.py report 1
```

### 5.2 `src/scanner.py`
Constants:
- `SECURITY_HEADERS` — dict of 4 headers + plain-English meaning.
- `PATHS` — `["/.git/HEAD", "/.env", "/robots.txt", "/admin"]`.
- `SEVERITY` — map from finding key to severity level.

Functions:
- `clean_url(url)` — adds `https://` if no scheme present.
- `fetch(url)` — `requests.get(url, timeout=10)`. No status-code check.
- `check_headers(headers)` — returns findings for missing security headers.
- `check_cookies(response)` — reads raw `Set-Cookie` lines; flags missing `Secure` / `HttpOnly`.
- `expiry_finding(cert)` — computes days until expiry; returns expired / expiring-soon finding or None.
- `check_tls(url)` — TLS version + cert expiry via `ssl`/`socket`; uses `requests.certs.where()` for CA bundle. Returns `(findings, info_string)`.
- `random_path_length(url)` — fetches a random non-existent path to get baseline length.
- `login_page(response)` — detects a real password field in HTML.
- `admin_exposed(response, random_length)` — heuristic: exposed if length differs from random path, content not HTML, or not a login page.
- `check_paths(url)` — GETs each path; records finding if HTTP 200 and not HTML (or admin exposed).
- `scan(url)` — orchestrates all checks; returns `(findings, tls_info)`.

### 5.3 `src/sca.py`
Constants:
- `OSV_URL` — `https://api.osv.dev/v1/query`
- `OUTPUT_DIR` — `<project>/output`
- `SEVERITY_MAP` — OSV severity → Low/Medium/High/Critical.

Functions:
- `split_requirement(text)` — strips env marker after `;`, splits name/version at first comparison operator.
- `parse_requirements(path)` — parses requirements.txt (skips blanks/comments/`-` lines and entries without usable version).
- `parse_package_json(path)` — parses `dependencies` + `devDependencies`; strips `^~><= `.
- `parse_manifest(path)` — dispatches by filename.
- `ecosystem(path)` — `"npm"` for package.json else `"PyPI"`.
- `query_osv(name, version, eco)` — POST to OSV; returns `vulns` list or `[]` on failure.
- `scan_manifest(path)` — builds list of item dicts with OSV results.
- `vuln_severity(vuln)` — from `database_specific.severity`, default Medium.
- `vuln_title(vuln, name, version)` — prefers CVE alias over OSV id.
- `vuln_description(vuln)` — joins summary + CVSS scores with `" | "`.
- `vuln_findings(items)` — flattens items/vulns into findings list.
- `save_sbom(items, manifest)` — writes `output/sbom.json` (overwrite).
- `__main__` block — allows running `python sca.py <manifest>` directly.

### 5.4 `src/db.py`
Constants:
- `DB_PATH` — `<project>/data/depguard.db`
- `SCHEMA` — 4 tables: `targets`, `scans`, `vulnerabilities`, `reports`.

Functions:
- `connect()` — opens connection, sets `row_factory = sqlite3.Row`, enables foreign keys.
- `init_db()` — executes schema (`CREATE TABLE IF NOT EXISTS`), idempotent.
- `get_or_create_target(kind, value)` — finds or inserts target row; returns id.
- `add_scan(target_id, scan_type)` — inserts scan row; returns id.
- `add_vulnerabilities(scan_id, findings)` — inserts vulnerability rows.
- `save_scan(kind, scan_type, value, findings)` — convenience: target + scan + vulns; returns scan_id.
- `list_scans()` — joins scans/targets, counts vulns per scan, ordered by id desc.
- `get_scan(scan_id)` — single scan dict or None.
- `list_vulnerabilities(scan_id)` — findings for a scan.
- `add_report(scan_id, file_path)` — records a generated report row.

### 5.5 `src/app.py` (Flask)
- `app = Flask(__name__)`; `MAX_CONTENT_LENGTH = 1 MiB`; calls `db.init_db()` at import.
- `url_scan(url)` — helper: clean + scan; returns `(scan_id, message)`.
- `manifest_scan(file)` — validates filename, saves to temp dir, scans, removes temp dir, saves SBOM (by name), returns `(scan_id, message)`.
- Routes:
  - `GET /` → `home()` → `home.html` with scans.
  - `GET /scan/<int:scan_id>` → `scan_details()` → `scan_details.html` or 404.
  - `GET /report/<int:scan_id>` → `download_report()` → `send_file` PDF or 404.
  - `GET/POST /new` → `new_scan()` → form handling + permission check.
- `if __name__ == "__main__": app.run(debug=True)` — runs on `127.0.0.1:5000`.

### 5.6 `src/report.py`
Constants:
- `OUTPUT_DIR` — `<project>/output`.
Functions:
- `clean(text)` — encodes to latin-1 with replacement (fpdf2 default font limitation).
- `severity_counts(findings)` — counts per severity.
- `write_header(pdf, scan, findings, counts)` — writes title, metadata, counts.
- `export_report(scan_id)` — builds PDF, saves `output/report_<id>.pdf`, records report row; returns path or None.

### 5.7 Templates
- `home.html` — navbar + scans table (ID, target, type, date, findings count) or empty state.
- `new_scan.html` — form: URL, manifest upload, permission checkbox, submit.
- `scan_details.html` — scan metadata + findings list with severity badges + "Download PDF" button.

---

## 6. Database Schema

SQLite database: `data/depguard.db`.

```sql
targets(id INTEGER PK, kind TEXT, value TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)
scans(id INTEGER PK, target_id INTEGER FK->targets.id, scan_type TEXT, created_at TEXT)
vulnerabilities(id INTEGER PK, scan_id INTEGER FK->scans.id, title TEXT, severity TEXT, description TEXT)
reports(id INTEGER PK, scan_id INTEGER FK->scans.id, file_path TEXT, created_at TEXT)
```

- `kind`: `'url'` or `'manifest'`.
- `scan_type`: `'url'` or `'sca'`.
- Foreign keys enabled in `connect()` (`PRAGMA foreign_keys = ON`).
- `get_or_create_target` prevents duplicate targets (same kind+value).

---

## 7. Data Paths

| Artifact | Path (relative to project root) | Produced by |
|---|---|---|
| SQLite DB | `data/depguard.db` | `db.py` (auto-created) |
| SBOM JSON | `output/sbom.json` | `sca.save_sbom` (overwritten each run) |
| PDF report | `output/report_<scan_id>.pdf` | `report.export_report` |

Paths are computed from `__file__`:
- `DB_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "depguard.db"))`
- `OUTPUT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output"))` (in both `sca.py` and `report.py`).

---

## 8. Key Decisions / Notes

- **No auth/CSRF/rate limiting** — dashboard is local-only by design (debug mode).
- **Permission gate** — URL scans require explicit confirmation (CLI prompt / web checkbox).
- **OSV failures are silent-ish** — `query_osv` prints "OSV query failed for <name>" and returns `[]`, so a failed query looks like "no vulnerabilities".
- **No HTTP status check in `fetch()`** — `requests.get` result is used without `.raise_for_status()`.
- **SBOM overwrite** — `save_sbom` always writes to `output/sbom.json` (single file), not per-scan.
- **Report row per export** — `export_report` inserts a new `reports` row each time, even for the same scan_id.
- **PDF encoding** — fpdf2 default fonts are latin-1; `clean()` replaces non-latin-1 chars.
- **Admin detection heuristic** — compares response length to a random path; experimental threshold of 200 chars.
- **Python version** — project rule: 3.9-compatible; Docker uses 3.12; observed env 3.14.7.
- **Docs location** — `docs/` is absent inside project; `PROJECT.md`/`PROJECT_FULL.md` are outside project; only `WORKLOG.md` was available as attachment.
- **No tests directory** — no automated tests present.

---

## 9. Work Log / What Was Tested

From `WORKLOG.md` (external):
- 2 scans recorded at doc time; reports empty; output empty at doc time.
- DB path computed from `__file__`.

Read-only verification performed in this conversation:
- Read all `src/*.py`, templates, `requirements.txt`, `README.md`, `Dockerfile`, `.gitignore`, `WORKLOG.md`.
- Verified line counts: scanner 175, sca 158, db 149, app 92, cli 79, report 63, templates 45/38/36 (total 835).
- No application run, no tests executed, no data/output opened (per rules).

Known mismatches noted between docs and code:
- CLI described as "4 Typer commands" but actual: 3 commands + callback.
- `vuln_description` separator: docs said `\|` but code uses `" | "`.
- `output/` reported empty at doc time but may have changed since.

---

## 10. Known Risks

- No status-code check in `fetch()` → may treat error pages as valid.
- OSV failures look like "no vulnerabilities".
- PDF latin-1 replacement may corrupt non-Latin text.
- No auth/CSRF/rate-limit on dashboard.
- Experimental `/admin` threshold (200 chars).
- Password-field-based login detection (heuristic).
- SBOM overwrite (single file).
- Reports row created per export (duplicates).
- Raw cookie header parsing depends on `response.raw.headers.getlist`.
- Docker untested; dashboard not browser-tested after latest changes.
- No automated tests.

---

## 11. How to Run (from README/docs)

```
# install
pip install -r requirements.txt

# URL scan (CLI)
python src/cli.py scan-url https://example.com

# Manifest scan (CLI)
python src/cli.py scan-manifest requirements.txt

# PDF report (CLI)
python src/cli.py report 1

# Dashboard
python src/app.py
# then open http://127.0.0.1:5000

# Docker
docker build -t depguard .
docker run -p 5000:5000 depguard
```

---

*End of documentation. No source files were modified.*