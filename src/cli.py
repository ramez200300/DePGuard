import requests
import typer

import db
import sca
import scanner
from report import export_report

app = typer.Typer()


@app.callback()
def main():
    db.init_db()


@app.command()
def scan_url(url):
    answer = typer.prompt("Do you own this target or have permission to test it? (y/n)")
    if answer.strip().lower() not in ("y", "yes"):
        print("Scan cancelled.")
        raise typer.Exit()

    url = scanner.clean_url(url)
    print("Target:", url)
    try:
        findings, tls_info = scanner.scan(url)
    except Exception:
        print("Could not fetch the URL. Check the address or your connection.")
        raise typer.Exit()

    if tls_info:
        print(tls_info)
    for finding in findings:
        print(finding["severity"], "-", finding["title"])
    if not findings:
        print("No findings")

    score, level = sca.calculate_risk_score(findings)
    print("Overall risk:", level, "(score " + str(score) + ")")
    scan_id = db.save_scan("url", "url", url, findings,
                           risk_score=score, risk_level=level)
    print("Saved scan", scan_id)


@app.command()
def scan_manifest(path):
    print("Manifest:", path)
    try:
        items = sca.scan_manifest(path)
    except (ValueError, requests.exceptions.RequestException) as error:
        typer.echo("Error: " + str(error), err=True)
        raise typer.Exit(code=1)

    for item in items:
        print(item["name"], item["version"], "-", len(item["vulns"]), "vulnerabilities")
    sbom_path = sca.save_sbom(items, path)
    print("SBOM saved to", sbom_path)

    findings = sca.vuln_findings(items)
    score, level = sca.calculate_risk_score(findings)
    print("Overall risk:", level, "(score " + str(score) + ")")
    scan_id = db.save_scan("manifest", "sca", path, findings, sbom_path,
                           risk_score=score, risk_level=level)
    print("Saved scan", scan_id)


@app.command()
def report(scan_id):
    try:
        scan_id = int(scan_id)
    except ValueError:
        print("Scan ID must be a number.")
        raise typer.Exit()

    path = export_report(scan_id)
    if not path:
        print("Scan not found.")
        raise typer.Exit()
    print("Report saved to", path)


if __name__ == "__main__":
    app()
