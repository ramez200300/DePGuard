import os
import shutil
import tempfile

import requests
from flask import Flask, redirect, render_template, request, send_file, url_for

import db
import report
import sca
import scanner

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
db.init_db()


def url_scan(url):
    url = scanner.clean_url(url)
    try:
        findings, _ = scanner.scan(url)
    except Exception:
        return None, "Could not fetch the URL. Check the address or your connection."
    score, level = sca.calculate_risk_score(findings)
    scan_id = db.save_scan("url", "url", url, findings,
                           risk_score=score, risk_level=level)
    return scan_id, ""


def manifest_scan(file):
    name = os.path.basename(file.filename)
    if name not in ("requirements.txt", "package.json"):
        return None, "Only requirements.txt or package.json is allowed."
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, name)
    file.save(path)
    try:
        items = sca.scan_manifest(path)
    except (ValueError, requests.exceptions.RequestException) as error:
        return None, str(error)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    sbom_path = sca.save_sbom(items, name)
    findings = sca.vuln_findings(items)
    score, level = sca.calculate_risk_score(findings)
    scan_id = db.save_scan("manifest", "sca", name, findings, sbom_path,
                           risk_score=score, risk_level=level)
    return scan_id, ""


@app.route("/")
def home():
    return render_template("home.html", scans=db.list_scans())


@app.route("/scan/<int:scan_id>")
def scan_details(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return "Scan not found", 404
    findings = db.list_vulnerabilities(scan_id)
    return render_template("scan_details.html", scan=scan, findings=findings)


@app.route("/report/<int:scan_id>")
def download_report(scan_id):
    path = report.export_report(scan_id)
    if not path:
        return "Scan not found", 404
    return send_file(path, as_attachment=True)


@app.route("/sbom/<int:scan_id>")
def download_sbom(scan_id):
    scan = db.get_scan(scan_id)
    if not scan or not scan.get("sbom_path"):
        return "SBOM not found", 404
    path = scan["sbom_path"]
    if not os.path.isfile(path):
        return "SBOM not found", 404
    try:
        return send_file(path, as_attachment=True)
    except OSError:
        
        return "SBOM not found", 404


@app.route("/new", methods=["GET", "POST"])
def new_scan():
    message = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        manifest = request.files.get("manifest")
        if url:
            if not request.form.get("permission"):
                message = "Confirm that you own the target or have permission to test it."
            else:
                scan_id, message = url_scan(url)
                if scan_id:
                    return redirect(url_for("scan_details", scan_id=scan_id))
        elif manifest and manifest.filename:
            scan_id, message = manifest_scan(manifest)
            if scan_id:
                return redirect(url_for("scan_details", scan_id=scan_id))
        else:
            message = "Enter a URL or choose a manifest file."
    return render_template("new_scan.html", message=message)


if __name__ == "__main__":
    app.run(debug=True)
