import json
import os
import sys
from datetime import datetime

import requests

OSV_URL = "https://api.osv.dev/v1/query"
OUTPUT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output"))

# ترجمة شدة OSV إلى المستويات الأربعة
SEVERITY_MAP = {"LOW": "Low", "MODERATE": "Medium", "HIGH": "High", "CRITICAL": "Critical"}


def split_requirement(text):
    # نحذف شرط البيئة بعد ; ثم نفصل الاسم عن الإصدار عند أول رمز مقارنة
    text = text.split(";")[0]
    for operator in ("==", ">=", "<=", "~=", "!=", ">", "<", "="):
        if operator in text:
            name, version = text.split(operator, 1)
            return name.split("[")[0].strip(), version.strip()
    return text.split("[")[0].strip(), ""


def parse_requirements(path):
    packages = []
    with open(path, encoding="utf-8") as file:
        for line in file:
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            name, version = split_requirement(line)
            if not version or not version[0].isdigit():
                print("Skipped:", name, "- no usable version")
                continue
            packages.append((name, version))
    return packages


def parse_package_json(path):
    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    packages = []
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            # نأخذ أول جزء من المدى ونحذف رموز ^ ~ >= <= > < =
            version = version.split(" ")[0].lstrip("^~><= ")
            if not version or not version[0].isdigit():
                print("Skipped:", name, "- version", version)
                continue
            packages.append((name, version))
    return packages


def parse_manifest(path):
    if path.endswith("package.json"):
        return parse_package_json(path)
    return parse_requirements(path)


def ecosystem(path):
    if path.endswith("package.json"):
        return "npm"
    return "PyPI"


def query_osv(name, version, eco):
    body = {
        "package": {"name": name, "ecosystem": eco},
        "version": version,
    }
    try:
        response = requests.post(OSV_URL, json=body, timeout=15)
        response.raise_for_status()
        return response.json().get("vulns", [])
    except Exception:
        print("OSV query failed for", name)
        return []


def scan_manifest(path):
    eco = ecosystem(path)
    items = []
    for name, version in parse_manifest(path):
        items.append({
            "name": name,
            "version": version,
            "ecosystem": eco,
            "vulns": query_osv(name, version, eco),
        })
    return items


def vuln_severity(vuln):
    details = vuln.get("database_specific") or {}
    return SEVERITY_MAP.get(details.get("severity", "").upper(), "Medium")


def vuln_title(vuln, name, version):
    identifier = vuln.get("id", "unknown")
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            identifier = alias
            break
    return identifier + " in " + name + " " + version


def vuln_description(vuln):
    parts = [vuln.get("summary", "")]
    for score in vuln.get("severity", []):
        parts.append(score.get("score", ""))
    return " | ".join([part for part in parts if part])


def vuln_findings(items):
    findings = []
    for item in items:
        for vuln in item["vulns"]:
            findings.append({
                "title": vuln_title(vuln, item["name"], item["version"]),
                "severity": vuln_severity(vuln),
                "description": vuln_description(vuln),
            })
    return findings


def save_sbom(items, manifest):
    packages = []
    for item in items:
        vulns = []
        for vuln in item["vulns"]:
            vulns.append({"id": vuln.get("id"), "summary": vuln.get("summary", "")})
        packages.append({
            "name": item["name"],
            "version": item["version"],
            "ecosystem": item["ecosystem"],
            "vulnerabilities": vulns,
        })
    data = {
        "manifest": manifest,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "packages": packages,
    }
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "sbom.json")
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
    return path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sca.py <requirements.txt|package.json>")
    else:
        items = scan_manifest(sys.argv[1])
        for item in items:
            print(item["name"], item["version"], "-", len(item["vulns"]), "vulnerabilities")
        print("SBOM saved to", save_sbom(items, sys.argv[1]))
