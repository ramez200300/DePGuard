# DePGuard
DAST-lite scan of a URL you own or have permission to test: TLS, headers, cookies, exposed paths.
Dependency scan of requirements.txt or package.json: CVEs from OSV.dev plus an sbom.json file.
Findings get Low/Medium/High/Critical, saved in SQLite, shown in a dashboard, exported to PDF.

## Install

python -m venv .venv
.venv\Scripts\activate        (Windows CMD; Git Bash: source .venv/Scripts/activate)
pip install -r requirements.txt

## Run
python src/cli.py scan-url https://example.com
python src/cli.py scan-manifest requirements.txt
python src/cli.py report 1        (PDF; dashboard: python src/app.py, then http://127.0.0.1:5000)
