# PRD: DePGuard

## Problem
Modern web applications face two major security challenges: runtime misconfigurations (missing security headers, weak TLS) and supply chain vulnerabilities (outdated third-party dependencies). Security students and small development teams often lack a single, lightweight tool that addresses both issues without complex setup or expensive commercial licenses.

## Users
- Primary: Cybersecurity students and small development teams (using CLI).
- Secondary: Instructors or reviewers (using the web dashboard for reports).

## Goal
Provide an integrated, lightweight security auditing platform (DAST + SCA) that scans web targets and dependency manifests, stores results locally, and generates clear PDF reports and SBOMs.

## Success Metrics
- Scan and SCA complete within 30-60 seconds.
- PDF reports generate correctly without character encoding errors.
- Dashboard successfully displays scan history and findings.

## Core Features
1. URL Scan (DAST): Checks missing HTTP headers, cookie flags, TLS version, and exposed sensitive paths.
2. Manifest Scan (SCA): Parses requirements.txt and package.json, queries OSV API, and generates an SBOM.
3. Local Persistence: Uses SQLite to store scan history and findings.
4. PDF Reporting: Generates downloadable executive reports for scans.
5. Flask Dashboard: A web interface to view scans and trigger new ones.
6. CLI Interface: Typer-based commands for terminal usage.

## Non-Goals
- Advanced fuzzing or input injection (no XSS/SQLi payload fuzzing).
- Business logic flaw detection.
- Multi-user authentication for the dashboard.
- Direct NVD/MITRE API integration (OSV is sufficient for v1).
- Docker deployment (deferred to LATER due to environment constraints).

## Constraints
- Deadline: ~1.5 months.
- Team size: 1 (Student project).
- Must use: Python 3.9+, Typer, Flask, SQLite, fpdf2, requests.