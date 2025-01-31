import os
import json
import time
import requests
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# API URLs
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
EXPLOIT_DB_SEARCH = "https://www.exploit-db.com/search?cve="

# Rate Limit Handling
NVD_RATE_LIMIT = 6  # 6 requests per 30 seconds
NVD_SLEEP_TIME = 30  # Sleep for 30 seconds if needed

def extract_cves_from_cyclonedx(sbom_file):
    """Extract CVEs from a CycloneDX JSON SBOM file."""
    try:
        with open(sbom_file, "r") as file:
            sbom_data = json.load(file)

        cve_list = set()
        
        if "vulnerabilities" in sbom_data:
            for vuln in sbom_data["vulnerabilities"]:
                cve_id = vuln.get("id")
                if cve_id and cve_id.startswith("CVE-"):
                    cve_list.add(cve_id)

        return list(cve_list)

    except Exception as e:
        print(f"Error reading SBOM file {sbom_file}: {e}")
        return []

def fetch_epss_scores(cve_list):
    """Fetch EPSS scores for a list of CVEs."""
    if not cve_list:
        return {}

    try:
        cve_query = ",".join(cve_list)
        url = f"{EPSS_API}?cve={cve_query}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return {entry["cve"]: entry["epss"] for entry in data.get("data", [])}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching EPSS scores: {e}")
        return {}

def fetch_kev_entries(cve_list):
    """Check if CVEs are listed in the CISA KEV database."""
    try:
        response = requests.get(KEV_API)
        response.raise_for_status()
        kev_data = response.json()
        kev_cves = {entry["cveID"] for entry in kev_data.get("vulnerabilities", [])}
        return {cve: cve in kev_cves for cve in cve_list}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching KEV data: {e}")
        return {}

# Load processed vulnerability data
with open("vulnerability_report.json", "r") as file:
    results = json.load(file)

# Extract Data for Plotting
epss_scores = [entry["EPSS_Score"] for entry in results if entry["EPSS_Score"] is not None]
cvss_scores = [entry["CVSS_Score"] for entry in results if entry["CVSS_Score"] is not None]
kev_counts = sum(1 for entry in results if entry["In_KEV"])

# Ensure `summary.md` exists before appending
summary_file = "summary.md"
if not os.path.exists(summary_file):
    with open(summary_file, "w") as f:
        f.write("# 📊 Vulnerability Scan Summary\n\n")

# Append Chart Summary to `summary.md`
with open(summary_file, "a") as summary:
    summary.write("\n## 📈 Charts Summary\n")
    summary.write(f"- 🛡️ **Total KEV CVEs:** {kev_counts}\n")
    if epss_scores:
        summary.write(f"- 📉 **Average EPSS Score:** {np.mean(epss_scores):.2f}\n")
    if cvss_scores:
        summary.write(f"- 💣 **Average CVSS Score:** {np.mean(cvss_scores):.1f}\n")

print("✅ Chart insights appended to summary.md")

# Generate EPSS Score Distribution
plt.figure(figsize=(10, 5))
plt.hist(epss_scores, bins=10, color="blue", alpha=0.7, edgecolor="black")
plt.xlabel("EPSS Score")
plt.ylabel("Number of CVEs")
plt.title("EPSS Score Distribution")
plt.grid(True)
plt.savefig("charts/epss_distribution.png")
plt.close()

# Generate CVSS Score Distribution
plt.figure(figsize=(10, 5))
plt.hist(cvss_scores, bins=np.arange(0, 10.5, 0.5), color="green", alpha=0.7, edgecolor="black")
plt.xlabel("CVSS Score")
plt.ylabel("Number of CVEs")
plt.title("CVSS Score Distribution")
plt.grid(True)
plt.savefig("charts/cvss_distribution.png")
plt.close()

# Generate KEV Coverage Pie Chart
plt.figure(figsize=(6, 6))
labels = ["In KEV", "Not in KEV"]
sizes = [kev_counts, len(results) - kev_counts]
colors = ["red", "gray"]
plt.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors, startangle=140, shadow=True)
plt.title("KEV Coverage")
plt.savefig("charts/kev_pie_chart.png")
plt.close()

print("📊 Charts generated and saved in 'charts' directory.")
