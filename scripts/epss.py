import os
import json
import time
import requests
from pathlib import Path

# API URLs
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
EXPLOIT_DB_SEARCH = "https://www.exploit-db.com/search?cve="  # No API, just lookup

# Rate Limit Handling
NVD_RATE_LIMIT = 6  # NVD allows only 6 requests per 30 seconds
NVD_SLEEP_TIME = 30  # Sleep if rate limit exceeded

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

def fetch_nvd_data(cve_id):
    """Fetch NVD CVSS data."""
    url = f"{NVD_API_BASE}{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            return "N/A"
        if response.status_code != 200:
            print(f"Error fetching NVD data for {cve_id}: HTTP {response.status_code}")
            return "N/A"
        data = response.json()
        impact_data = data.get("result", {}).get("CVE_Items", [{}])[0].get("impact", {})
        base_metric = impact_data.get("baseMetricV3", {}).get("cvssV3", {})
        return base_metric.get("baseScore", "N/A")
    except requests.exceptions.RequestException as e:
        print(f"Request error for {cve_id}: {e}")
        return "N/A"

def scan_sboms(directory):
    """Scan multiple SBOM files for CVEs and check against KEV, EPSS, NVD, and ExploitDB."""
    results = []
    
    for sbom_file in Path(directory).glob("*.json"):
        print(f"Processing: {sbom_file}")
        if "cyclonedx" in sbom_file.name.lower():
            with open(sbom_file, "r") as file:
                sbom_data = json.load(file)
            cve_list = {vuln.get("id") for vuln in sbom_data.get("vulnerabilities", []) if vuln.get("id", "").startswith("CVE-")}
        else:
            continue  

        epss_scores = fetch_epss_scores(cve_list)
        kev_results = fetch_kev_entries(cve_list)

        for cve in cve_list:
            cvss_score = fetch_nvd_data(cve)  
            exploit_db_link = f"{EXPLOIT_DB_SEARCH}{cve}"  

            results.append({
                "CVE": cve,
                "EPSS_Score": float(epss_scores.get(cve, 0)),
                "CVSS_Score": float(cvss_score) if cvss_score != "N/A" else None,
                "In_KEV": kev_results.get(cve, False),
                "ExploitDB_Link": exploit_db_link
            })

    return results

def save_report(results, output_file):
    """Save results to a JSON file."""
    with open(output_file, "w") as file:
        json.dump(results, file, indent=4)
    print(f"Vulnerability report saved to {output_file}")

def generate_summary(results, summary_file):
    """Generate a summary report for GitHub Actions."""
    epss_scores = [entry["EPSS_Score"] for entry in results if entry["EPSS_Score"] is not None]
    cvss_scores = [entry["CVSS_Score"] for entry in results if entry["CVSS_Score"] is not None]
    kev_cves = [entry["CVE"] for entry in results if entry["In_KEV"]]

    summary_content = []
    summary_content.append("# Vulnerability Scan Report\n")
    summary_content.append(f"- **Total CVEs Scanned:** {len(results)}\n")
    summary_content.append(f"- **CVEs in KEV Database:** {len(kev_cves)}\n")

    if epss_scores:
        summary_content.append(f"- **Highest EPSS Score:** {max(epss_scores):.2f}\n")
    if cvss_scores:
        summary_content.append(f"- **Highest CVSS Score:** {max(cvss_scores):.1f}\n")

    if kev_cves:
        summary_content.append("\n### Top 5 CVEs in KEV Database:\n")
        for cve in kev_cves[:5]:
            summary_content.append(f"- {cve}\n")

    # Save summary
    with open(summary_file, "w") as summary:
        summary.writelines(summary_content)

    print("Summary report saved to summary.md")

if __name__ == "__main__":
    sbom_dir = "./"  
    report_file = "vulnerability_report.json"
    summary_file = "summary.md"

    results = scan_sboms(sbom_dir)
    save_report(results, report_file)
    generate_summary(results, summary_file)
