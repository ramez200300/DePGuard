import typer

import db
import sca
import scanner
from report import export_report

app = typer.Typer()


# callback فارغ، بدونه يعامل Typer التطبيق كأمر واحد ولا يظهر scan-url كأمر
@app.callback()
def main():
    # ننشئ الجداول إن لم تكن موجودة قبل أي أمر
    db.init_db()


@app.command()
def scan_url(url):
    # لا نفحص أي رابط قبل تأكيد الملكية أو الإذن
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

    scan_id = db.save_scan("url", "url", url, findings)
    print("Saved scan", scan_id)


@app.command()
def scan_manifest(path):
    print("Manifest:", path)
    try:
        items = sca.scan_manifest(path)
    except Exception:
        print("Could not read the manifest. Check the path and the file format.")
        raise typer.Exit()

    for item in items:
        print(item["name"], item["version"], "-", len(item["vulns"]), "vulnerabilities")
    print("SBOM saved to", sca.save_sbom(items, path))

    findings = sca.vuln_findings(items)
    scan_id = db.save_scan("manifest", "sca", path, findings)
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
