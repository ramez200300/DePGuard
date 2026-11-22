# DePGuard

**An Integrated Web Vulnerability and Dependency Scanner**

DePGuard is a lightweight security scanner that combines Dynamic Application Security Testing (DAST) and Software Composition Analysis (SCA) in one tool. It probes a web target for common configuration weaknesses, analyzes project dependencies for known vulnerabilities through the OSV API, stores every result locally in SQLite, and produces PDF reports and SBOM files.

The same engine is available through two interfaces: a command-line tool for repeatable checks and a web dashboard for reviewing history. Both write to the same local database, so a scan started in one place can be inspected or exported from the other.

## Features

- **URL Scanning (DAST):** Checks TLS configuration, security headers, cookie flags, and a set of commonly exposed paths on a target you own or have permission to test.
- **Manifest Scanning (SCA):** Reads `requirements.txt` or `package.json`, queries the OSV API for each dependency, and maps the results to Low, Medium, High, and Critical severities.
- **Risk Scoring:** Aggregates all findings of a scan into a single score using severity weights (Critical 10, High 5, Medium 2, Low 1) and classifies it as Safe, Low Risk, Medium Risk, High Risk, or Critical Risk.
- **PDF Reports:** Generates a readable report for any saved scan with target details, severity counts, the overall risk score, and the individual findings.
- **SBOM Generation:** Writes a JSON Software Bill of Materials for every dependency scan and serves it for download from the dashboard.
- **Command-Line Interface:** Runs URL scans, dependency scans, and report generation through three Typer commands.
- **Web Dashboard:** Lists previous scans, starts new scans, shows findings and risk badges, and downloads PDF and SBOM files.

## Tech Stack

- **Python 3.9+** with the standard library wherever possible
- **Typer** for the command-line interface
- **Flask** for the web dashboard
- **SQLite** for local storage through the `sqlite3` module, without an ORM
- **fpdf2** for PDF report generation
- **OSV API** for dependency vulnerability data
- **requests** for HTTP communication and API calls

The dashboard uses Bootstrap 5 from a CDN for its layout and styling.

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd DePGuard
```

Create a virtual environment and install the dependencies on Windows CMD:

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

All commands below are run from the project root.

## Usage (CLI)

### Scan a URL

```cmd
python src/cli.py scan-url https://example.com
```

The command asks you to confirm that you own the target or have permission to test it. It then prints the findings, shows the overall risk level with its score, and saves the scan with an ID that can be used for reporting.

### Scan a dependency manifest

```cmd
python src/cli.py scan-manifest samples/vulnerable_requirements.txt
```

The manifest must be named `requirements.txt` or `package.json`. DePGuard queries OSV for every dependency, prints a per-package summary and the overall risk, saves the findings, and writes a timestamped SBOM file to `output/`.

### Generate a PDF report

```cmd
python src/cli.py report 1
```

Replace `1` with the scan ID printed by a previous scan. The report is written to `output/report_<scan-id>.pdf`.

## Usage (Web Dashboard)

Start the Flask application from the project root:

```cmd
python src/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

From the dashboard you can review previous scans with their risk badges, start a new URL or manifest scan, inspect the findings of a scan, and download its PDF report or SBOM.

## Running Tests

The test suite uses the standard library `unittest` module, so no extra test dependency is required:

```cmd
python -m unittest discover -s tests
```

Add `-v` for a per-test listing. The tests cover URL scanner helpers, manifest parsing and finding generation, database operations and schema migration, SBOM storage and download routes, and the main dashboard pages.

## Project Structure

```text
DePGuard/
├── src/
│   ├── app.py              # Flask dashboard and HTTP routes
│   ├── cli.py              # Typer commands
│   ├── db.py               # SQLite schema, migration, and data access
│   ├── report.py           # PDF report generation
│   ├── sca.py              # Manifest parsing, OSV queries, risk scoring, SBOM
│   ├── scanner.py          # URL scanning checks
│   └── templates/          # Bootstrap dashboard pages
├── data/
│   └── depguard.db         # Local database, created at runtime
├── output/                 # Generated PDF reports and SBOM files
├── tests/                  # unittest test suite
├── samples/                # Intentionally vulnerable manifests for testing
├── requirements.txt        # Python dependencies
└── README.md
```

- **`src/`** holds all application code. The CLI and the dashboard share the scanner, SCA, database, and reporting modules.
- **`data/`** contains the SQLite database. It is created on first run and older databases are upgraded automatically when new columns are introduced.
- **`output/`** receives everything DePGuard generates: `report_<id>.pdf` files and `sbom_*.json` files.
- **`tests/`** contains the `unittest` suite run by the command above.
- **`samples/`** provides deliberately outdated dependency manifests for safe demonstration scans.
