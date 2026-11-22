import socket
import ssl
import time
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP limits which scripts the browser can run",
    "X-Frame-Options": "blocks framing and clickjacking",
    "Strict-Transport-Security": "HSTS forces HTTPS on later visits",
    "X-Content-Type-Options": "stops browsers from guessing content types",
}

PATHS = ["/.git/HEAD", "/.env", "/robots.txt", "/admin"]

SEVERITY = {
    "Content-Security-Policy": "Medium",
    "X-Frame-Options": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Content-Type-Options": "Low",
    "cookie_secure": "Medium",
    "cookie_httponly": "Medium",
    "old_tls": "High",
    "expired_cert": "High",
    "expiring_soon": "Medium",
    "tls_error": "High",
    "/.git/HEAD": "High",
    "/.env": "Critical",
    "/robots.txt": "Low",
    "/admin": "Medium",
}


def clean_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "https://" + url
    return url


def fetch(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response


def check_headers(headers):
    findings = []
    for name in SECURITY_HEADERS:
        if name not in headers:
            findings.append({
                "title": "Missing header: " + name,
                "severity": SEVERITY[name],
                "description": SECURITY_HEADERS[name],
            })
    return findings


def check_cookies(response):
    findings = []
    for line in response.raw.headers.getlist("Set-Cookie"):
        name = line.split("=")[0].strip()
        attributes = [part.strip().lower() for part in line.split(";")[1:]]
        if "secure" not in attributes:
            findings.append({
                "title": "Cookie without Secure: " + name,
                "severity": SEVERITY["cookie_secure"],
                "description": "Cookie can be sent over plain HTTP",
            })
        if "httponly" not in attributes:
            findings.append({
                "title": "Cookie without HttpOnly: " + name,
                "severity": SEVERITY["cookie_httponly"],
                "description": "JavaScript can read this cookie",
            })
    return findings


def expiry_finding(cert):
    days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
    if days < 0:
        return {"title": "Certificate expired",
                "severity": SEVERITY["expired_cert"],
                "description": "Expired on " + cert["notAfter"]}
    if days < 30:
        return {"title": "Certificate expires in " + str(days) + " days",
                "severity": SEVERITY["expiring_soon"],
                "description": "Expires on " + cert["notAfter"]}
    return None


def check_tls(url):
    parts = urlparse(url)
    port = parts.port or 443
    context = ssl.create_default_context()
    context.load_verify_locations(requests.certs.where())
    try:
        with socket.create_connection((parts.hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=parts.hostname) as tls:
                version = tls.version()
                cert = tls.getpeercert()
    except Exception as e:
        return [{"title": "TLS check failed", "severity": SEVERITY["tls_error"],
                 "description": str(e)}], ""

    info = "TLS version: " + version + ", certificate expires: " + cert["notAfter"]
    findings = []
    if version in ("TLSv1", "TLSv1.1"):
        findings.append({"title": "Old TLS version: " + version,
                         "severity": SEVERITY["old_tls"],
                         "description": "TLS 1.2 or newer is recommended"})
    expiry = expiry_finding(cert)
    if expiry:
        findings.append(expiry)
    return findings, info


def random_path_length(url):
    try:
        return len(requests.get(url.rstrip("/") + "/zxq93k", timeout=10).text)
    except Exception:
        return None


def login_page(response):
    body = response.text.lower().replace("'", '"')
    return 'type="password"' in body or 'name="password"' in body


def admin_exposed(response, random_length):
    if random_length is None or abs(len(response.text) - random_length) < 200:
        return False
    if "text/html" not in response.headers.get("Content-Type", "").lower():
        return True
    return not login_page(response)


def check_paths(url):
    findings = []
    random_length = random_path_length(url)
    for path in PATHS:
        try:
            response = requests.get(url.rstrip("/") + path, timeout=10, allow_redirects=False)
        except Exception:
            continue
        content_type = response.headers.get("Content-Type", "").lower()
        if response.status_code != 200:
            continue
        if path == "/admin":
            if not admin_exposed(response, random_length):
                continue
        elif "text/html" in content_type:
            continue
        if path == "/.git/HEAD" and not response.text.startswith("ref:"):
            continue
        findings.append({"title": "Exposed path: " + path,
                         "severity": SEVERITY[path],
                         "description": "Path returned HTTP 200"})
    return findings


def scan(url):
    try:
        response = fetch(url)
    except requests.exceptions.RequestException as error:
        message = "Could not fetch the target URL. It might be down or returning an error status."
        raise ValueError(message) from error
    findings = check_headers(response.headers)
    findings += check_cookies(response)
    tls_findings, tls_info = check_tls(url)
    findings += tls_findings
    findings += check_paths(url)
    return findings, tls_info
