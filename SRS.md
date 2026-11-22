# SRS: DePGuard

## Functional Requirements
| ID | Requirement | Acceptance Criterion (AC) |
|----|-------------|---------------------------|
| FR-01 | System must scan URL HTTP Security Headers | When scanning a URL missing CSP/HSTS, return a finding with proper severity (Medium/Low). |
| FR-02 | System must verify TLS/SSL configuration | When scanning HTTPS, return TLS version and certificate expiry date. |
| FR-03 | System must check for exposed sensitive paths | When scanning, check `/.git/HEAD`, `/.env`, `/robots.txt`, `/admin` and report 200 OK responses. |
| FR-04 | System must parse `requirements.txt` | When provided with `requirements.txt`, correctly extract library names and versions. |
| FR-05 | System must parse `package.json` | When provided with `package.json`, extract dependencies and devDependencies. |
| FR-06 | System must query OSV API for vulnerabilities | When a manifest is scanned, send a POST request to OSV API and return a list of vulnerabilities (or empty if none). |
| FR-07 | System must generate a Software Bill of Materials (SBOM) | When a manifest is scanned, save a `sbom.json` file in the `output/` directory. |
| FR-08 | System must store scan results in SQLite | When a scan finishes, save target, scan type, and findings to `data/depguard.db`. |
| FR-09 | System must generate PDF reports | When requesting a report for a valid scan ID, generate a `report_<id>.pdf` with metadata and findings. |
| FR-10 | CLI must support 3 commands | `python src/cli.py scan-url`, `scan-manifest`, and `report` must execute without errors. |
| FR-11 | Web Dashboard must list scans | `GET /` must display a table of past scans and their findings count. |
| FR-12 | Web Dashboard must allow new scans | `POST /new` must accept a URL or file upload and trigger a scan. |
| FR-13 | System must require permission for URL scans | CLI prompts (y/n) and Dashboard requires a checkbox before executing a URL scan. |

## Non-Functional Requirements
| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Performance | A single URL or Manifest scan should complete in < 60 seconds. |
| NFR-02 | Compatibility | Code must run on Python 3.9+ (tested on 3.14) without external C-extensions. |
| NFR-03 | Security | No secrets in code. URL scans require explicit user permission. |
| NFR-04 | Readability | Code must be understandable by a Bachelor's student (no complex async/ORM). |

## Data
- Entities: Target (URL or Manifest path), Scan, Vulnerability (Finding), Report.
- Key fields: Scan ID, Scan Type ('url' or 'sca'), Severity ('Low', 'Medium', 'High', 'Critical'), Description.

## API (Web Dashboard)
| Method | Path | Success | Errors |
|--------|------|---------|--------|
| GET | / | 200 (List scans) | 500 |
| GET | /new | 200 (Form) | - |
| POST | /new | 302 (Redirect to scan) | 400 (Missing input) |
| GET | /scan/<id> | 200 (Scan details) | 404 (Not found) |
| GET | /report/<id> | 200 (PDF file) | 404 (Not found) |