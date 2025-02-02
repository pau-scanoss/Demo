import json
import os
import numpy as np

# Ensure the reports directory exists
output_dir = "reports"
if not os.path.exists(output_dir):
    print(f"📁 Creating missing directory: {output_dir}")
    os.makedirs(output_dir)

# File path for vulnerability report
vuln_file = "vulnerability_report.json"

# Check if the vulnerability report exists
if not os.path.exists(vuln_file):
    print(f"⚠️ Warning: {vuln_file} not found. Generating an empty summary.")
    results = []
else:
    # Load the vulnerability report
    with open(vuln_file, "r", encoding="utf-8") as file:
        results = json.load(file)

# Ensure there's data in the report
if not results:
    print("⚠️ No vulnerabilities found. Creating a basic summary.")
    results = []

# Extract data safely and replace None with 0.0
for entry in results:
    entry["EPSS_Score"] = entry.get("EPSS_Score", 0.0) if isinstance(entry.get("EPSS_Score"), (int, float)) else 0.0
    entry["CVSS_Score"] = entry.get("CVSS_Score", 0.0) if isinstance(entry.get("CVSS_Score"), (int, float)) else 0.0

# Collecting valid scores for mean calculations
epss_scores = [entry["EPSS_Score"] for entry in results]
cvss_scores = [entry["CVSS_Score"] for entry in results]
kev_count = sum(1 for entry in results if entry.get("In_KEV", False))
total_cves = len(results)

# Categorize CVEs by risk
high_risk = [entry for entry in results if entry["EPSS_Score"] >= 0.7]
medium_risk = [entry for entry in results if 0.3 <= entry["EPSS_Score"] < 0.7]
low_risk = [entry for entry in results if entry["EPSS_Score"] < 0.3]

# Handle empty datasets to prevent mean calculation errors
avg_epss = np.mean(epss_scores) if epss_scores else 0.0
avg_cvss = np.mean(cvss_scores) if cvss_scores else 0.0

# Generate markdown report
summary_md = f"""
# 📊 Vulnerability Scan Summary

## 🛡️ Overview
- 🔎 **Total CVEs Scanned:** {total_cves}
- 🛑 **Total KEV CVEs:** {kev_count}
- 📉 **Average EPSS Score:** {avg_epss:.2f}
- 💣 **Average CVSS Score:** {avg_cvss:.1f}

---

## 🚨 High-Risk Vulnerabilities (EPSS > 0.7)
"""
summary_md += "\n".join(
    f"- **{cve['CVE']}** (EPSS: {cve['EPSS_Score']:.2f}) 🔴 [ExploitDB](https://www.exploit-db.com/search?cve={cve['CVE']})"
    for cve in high_risk
) if high_risk else "None"

summary_md += """

---

## ⚠️ Medium-Risk Vulnerabilities (0.3 < EPSS ≤ 0.7)
"""
summary_md += "\n".join(
    f"- **{cve['CVE']}** (EPSS: {cve['EPSS_Score']:.2f}) 🟠 [ExploitDB](https://www.exploit-db.com/search?cve={cve['CVE']})"
    for cve in medium_risk
) if medium_risk else "None"

summary_md += """

---

## ✅ Low-Risk Vulnerabilities (EPSS ≤ 0.3)
"""
summary_md += "\n".join(
    f"- **{cve['CVE']}** (EPSS: {cve['EPSS_Score']:.2f}) 🟢 [ExploitDB](https://www.exploit-db.com/search?cve={cve['CVE']})"
    for cve in low_risk
) if low_risk else "None"

summary_md += """

---

## 📈 Charts Summary
![EPSS Score Distribution](charts/epss_distribution.png)
![KEV Coverage](charts/kev_pie_chart.png)
![EPSS vs. CVSS](charts/epss_vs_cvss.png)

---

## 📜 Full CVE Report
<details>
<summary>Click to Expand Full Report</summary>

| CVE ID | EPSS Score | CVSS Score | In KEV? | ExploitDB |
|--------|------------|------------|--------|-----------|
"""
summary_md += "\n".join(
    f"| {entry['CVE']} | {entry['EPSS_Score']:.2f} | {entry['CVSS_Score']:.1f} | {'✅' if entry.get('In_KEV', False) else '❌'} | [Link](https://www.exploit-db.com/search?cve={entry['CVE']}) |"
    for entry in results
) if results else "| No vulnerabilities found | - | - | - | - |"

summary_md += """
</details>

---
"""

# Define correct output path
summary_path = os.path.join(output_dir, "summary.md")

# Write summary to file
with open(summary_path, "w", encoding="utf-8") as f:
    f.write(summary_md)

print(f"✅ Markdown report generated: {summary_path}")