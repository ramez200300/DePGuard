# MVP Scope: DePGuard
> What ships in version 1, and what does not. The agent builds IN only.

## IN (version 1)
- URL Scan: Security Headers, Cookies, TLS, 4 paths (DAST).
- Manifest Scan: requirements.txt & package.json via OSV API (SCA).
- SQLite Database: Store scans and findings locally.
- PDF Reports: Generate executive PDF reports for scans.
- Flask Dashboard: 4 routes to view scans, start new scans, and download reports.
- Typer CLI: 3 commands (scan-url, scan-manifest, report).

## OUT (not in version 1)
- Docker Containerization (Deferred due to local environment limitations).
- Authentication / Multi-user support for the dashboard.
- Direct NVD / MITRE API integration (using OSV only).
- Caching layer.
- Advanced Risk Scoring Engine (using simple severity mapping).
- Reachability analysis / Call graphs.

## LATER (after version 1 is used by real users)
- Verify and deploy Docker container.
- Implement caching for faster OSV queries.
- Add user authentication to the Flask dashboard.
- Implement CVSS scoring.

## Done means
- [x] Every IN feature passes its AC in SRS.md
- [x] Tests pass (Manual testing completed for 6 core features)
- [x] Deployed to Local environment (CLI & Web Dashboard)