import json
import os
import sys
from datetime import datetime

import requests

OSV_URL = "https://api.osv.dev/v1/query"
OUTPUT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output"))


SEVERITY_MAP = {"LOW": "Low", "MODERATE": "Medium", "HIGH": "High", "CRITICAL": "Critical"}


RISK_WEIGHTS = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}


def split_requirement(text):
    
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
            
            version = version.split(" ")[0].lstrip("^~><= ")
            if not version or not version[0].isdigit():
                print("Skipped:", name, "- version", version)
                continue
            packages.append((name, version))
    return packages


def parse_manifest(path):
    if os.path.getsize(path) == 0:
        raise ValueError("Manifest file is empty or invalid")
    if not path.endswith("package.json"):
        return parse_requirements(path)
    try:
        return parse_package_json(path)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise ValueError("Manifest file is empty or invalid") from error


def ecosystem(path):
    if path.endswith("package.json"):
        return "npm"
    return "PyPI"


def query_osv(name, version, eco):
    body = {
        "package": {"name": name, "ecosystem": eco},
        "version": version,
    }
    response = requests.post(OSV_URL, json=body, timeout=15)
    response.raise_for_status()
    return response.json().get("vulns", [])


def scan_manifest(path):
    try:
        packages = parse_manifest(path)
    except (OSError, ValueError) as error:
        raise ValueError("Manifest file is empty or invalid") from error
    if not packages:
        raise ValueError("Manifest file is empty or invalid")
    eco = ecosystem(path)
    items = []
    for name, version in packages:
        try:
            vulns = query_osv(name, version, eco)
        except requests.exceptions.RequestException as error:
            message = "OSV API failed for " + name + " " + version + " - scan stopped."
            print(message)
            raise requests.exceptions.RequestException(message) from error
        items.append({
            "name": name,
            "version": version,
            "ecosystem": eco,
            "vulns": vulns,
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
        value = score.get("score", "")
       
        if score.get("type") == "CVSS_V4" or value.upper().startswith("CVSS:4.0"):
            continue
        parts.append(value[:50])
    return " | ".join([part for part in parts if part])


def vuln_findings(items):
    findings = []
    seen = set()
    for item in items:
        for vuln in item["vulns"]:
            title = vuln_title(vuln, item["name"], item["version"])
            if title in seen:
                continue
            seen.add(title)
            findings.append({
                "title": title,
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
    now = datetime.now()
    data = {
        "manifest": manifest,
        "generated_at": now.isoformat(timespec="seconds"),
        "packages": packages,
    }
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    name = os.path.splitext(os.path.basename(manifest))[0]
    stamp = now.strftime("%Y%m%d_%H%M%S_%f")
    path = os.path.join(OUTPUT_DIR, "sbom_" + name + "_" + stamp + ".json")
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
    return path


def risk_classification(score):
    for limit, level in ((0, "Safe"), (10, "Low Risk"), (25, "Medium Risk"), (50, "High Risk")):
        if score <= limit:
            return level
    return "Critical Risk"


def calculate_risk_score(findings):
    score = sum(RISK_WEIGHTS.get(finding.get("severity", ""), 0) for finding in findings)
    return score, risk_classification(score)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sca.py <requirements.txt|package.json>")
    else:
        items = scan_manifest(sys.argv[1])
        for item in items:
            print(item["name"], item["version"], "-", len(item["vulns"]), "vulnerabilities")
        print("SBOM saved to", save_sbom(items, sys.argv[1]))
