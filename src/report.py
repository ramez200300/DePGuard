import os
from datetime import datetime

from fpdf import FPDF

import db
import sca

OUTPUT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output"))


def clean(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")


def severity_counts(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1
    return counts


def finding_height(pdf, finding):
    pdf.set_font("helvetica", "B", 10)
    title = finding["severity"] + " - " + clean(finding["title"])
    height = pdf.multi_cell(0, 6, title, dry_run=True, output="HEIGHT")
    pdf.set_font("helvetica", "", 9)
    height += pdf.multi_cell(0, 5, clean(finding["description"]), dry_run=True, output="HEIGHT")
    return height + 2


def write_header(pdf, scan, findings, counts):
    pdf.set_font("helvetica", "B", 16)
    pdf.multi_cell(0, 10, "DePGuard report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.multi_cell(0, 6, "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M"),
                   new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Scan ID: " + str(scan["id"]), new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Type: " + scan["scan_type"], new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Target: " + clean(scan["value"]), new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Date: " + scan["created_at"], new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Findings: " + str(len(findings)), new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Critical: " + str(counts["Critical"]) + "  High: " + str(counts["High"]),
                   new_x="LMARGIN", new_y="NEXT")
    pdf.multi_cell(0, 6, "Medium: " + str(counts["Medium"]) + "  Low: " + str(counts["Low"]),
                   new_x="LMARGIN", new_y="NEXT")
    score = scan.get("risk_score")
    level = scan.get("risk_level")
    if score is None or not level:
       
        score, level = sca.calculate_risk_score(findings)
    pdf.set_font("helvetica", "B", 12)
    pdf.multi_cell(0, 7, "Overall Risk Score: " + str(score) + " (" + level + ")",
                   new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.ln(3)


def export_report(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return None
    findings = db.list_vulnerabilities(scan_id)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    write_header(pdf, scan, findings, severity_counts(findings))
    for finding in findings:
        needed = finding_height(pdf, finding)
        if pdf.get_y() > pdf.t_margin and pdf.will_page_break(needed):
            pdf.add_page()
        pdf.set_font("helvetica", "B", 10)
        pdf.multi_cell(0, 6, finding["severity"] + " - " + clean(finding["title"]),
                       align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 9)
        pdf.multi_cell(0, 5, clean(finding["description"]),
                       align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "report_" + str(scan_id) + ".pdf")
    pdf.output(path)
    db.add_report(scan_id, os.path.basename(path))
    return path
