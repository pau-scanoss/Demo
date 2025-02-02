import os
import json
import numpy as np
import pandas as pd
from collections import Counter
from tabulate import tabulate

# Enable verbose logging
def log(message):
    print(f"🔹 {message}")

# Ensure output directory exists
output_dir = "reports"
if not os.path.exists(output_dir):
    log(f"📁 Creating missing directory: {output_dir}")
    os.makedirs(output_dir)

# File paths
vuln_file = "vulnerability_report.json"
sbom_file = "cycloneDX.json"  # ✅ Updated to match the correct file name
summary_file = os.path.join(output_dir, "summary.md")

# Load vulnerability report
if os.path.exists(vuln_file):
    log("📥 Loading vulnerability report...")
    with open(vuln_file, "r", encoding="utf-8") as file:
        results = json.load(file)
else:
    log(f"⚠️ Warning: {vuln_file} not found. Generating an empty summary.")
    results = []

# Ensure results contain data
if not results:
    log("⚠️ No vulnerabilities found. Creating a basic summary.")
    results = []

# Extract vulnerability data
for entry in results:
    entry["EPSS_Score"] = entry.get("EPSS_Score", 0.0) if isinstance(entry.get("EPSS_Score"), (int, float)) else 0.0
    entry["CVSS_Score"] = entry.get("CVSS_Score", 0.0) if isinstance(entry.get("CVSS_Score"), (int, float)) else 0.0

# Compute statistics
epss_scores = [entry["EPSS_Score"] for entry in results]
cvss_scores = [entry["CVSS_Score"] for entry in results]
kev_count = sum(1 for entry in results if entry.get("In_KEV", False))
total_cves = len(results)
avg_epss = np.mean(epss_scores) if epss_scores else 0.0
avg_cvss = np.mean(cvss_scores) if cvss_scores else 0.0

# Categorize vulnerabilities by EPSS risk levels
high_risk = [entry for entry in results if entry["EPSS_Score"] >= 0.7]
medium_risk = [entry for entry in results if 0.3 <= entry["EPSS_Score"] < 0.7]
low_risk = [entry for entry in results if entry["EPSS_Score"] < 0.3]

# 📥 Load SCANOSS SBOM data if available
licenses = []
components_metadata = []
crypto_algorithms = []
provenance_data = []

try:
    if os.path.exists(sbom_file):
        log(f"📥 Loading SCANOSS SBOM data from {sbom_file}...")
        with open(sbom_file, "r", encoding="utf-8") as file:
            content = file.read().strip()
            if not content:
                log(f"⚠️ Warning: {sbom_file} is empty. No SCANOSS metadata available.")
                data = {}
            else:
                data = json.loads(content)

        for component in data.get("components", []):
            if not isinstance(component, dict):  # ✅ Ensure component is a dictionary
                log(f"⚠️ Skipping invalid component entry: {component}")
                continue  

            # Extract licenses
            license_list = component.get("licenses", [])
            for license_info in license_list:
                if "license" in license_info:
                    licenses.append(license_info["license"].get("name", "Unknown License"))

            # Extract component metadata
            provenance = component.get("publisher", "Unknown")
            component_name = component.get("name", "Unknown Component")
            version = component.get("version", "N/A")
            author = component.get("publisher", "N/A")

            # Collect metadata for components
            components_metadata.append({
                "Component": component_name,
                "Version": version,
                "Author": author,
                "License": ", ".join(licenses) if licenses else "Unknown License",
                "Provenance": provenance
            })
    else:
        log(f"⚠️ Warning: {sbom_file} not found. No SCANOSS metadata available.")
        data = {}

except json.JSONDecodeError as e:
    log(f"❌ Error: Invalid JSON in {sbom_file}: {e}")
    data = {}

# Create DataFrames
license_df = pd.DataFrame({"License": licenses})
components_df = pd.DataFrame(components_metadata)

# Summarize SCANOSS data
license_summary = license_df["License"].value_counts().head(10).reset_index().values
provenance_summary = Counter(entry["Provenance"] for entry in components_metadata).items()

# 📝 Generate Markdown summary
summary_md = f"""
# 📊 SCANOSS SBOM & Vulnerability Report

## 🛡️ Vulnerability Overview
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

## 🔐 SCANOSS Insights

### Top 10 License Distribution
"""
summary_md += tabulate(license_summary, headers=["License", "Count"], tablefmt="github") if not license_df.empty else "No license data available."

summary_md += """

---

### Repository Component Metadata
"""
summary_md += tabulate(components_df.head(10), headers="keys", tablefmt="github") if not components_df.empty else "No component metadata available."

summary_md += """

### Provenance Summary
"""
summary_md += "\n".join([f"- **{country}**: {count} components" for country, count in provenance_summary]) if provenance_summary else "No provenance data available."

# Save summary
with open(summary_file, "w", encoding="utf-8") as f:
    f.write(summary_md)

log(f"✅ Summary markdown saved: {summary_file}")
