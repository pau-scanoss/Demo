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
NVD_SLEEP_TIME = 30  # Sleep for 30 seconds after hitting rate limit

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

        if "components" in sbom_data:
            for component in sbom_data["components"]:
                if "externalReferences" in component:
                    for ref in component["externalReferences"]:
                        if ref.get("type") == "vulnerability" and "url" in ref:
                            if "CVE-" in ref["url"]:
                                cve_id = ref["url"].split("/")[-1]
                                cve_list.add(cve_id)

        return list(cve_list)

    except Exception as e:
        print(f"Error reading SBOM file {sbom_file}: {e}")
        return []

def fetch_epss_scores(cve_list):
    """Fetch EPSS scores for a list of CVEs."""
    if not cve_list:
        return {}

    cve_query = ",".join(cve_list)
    url = f"{EPSS_API}?cve={cve_query}"
    response = requests.get(url)

    try:
        data = response.json()
        return {entry["cve"]: entry["epss"] for entry in data.get("data", [])}
    except Exception as e:
        print(f"Error fetching EPSS scores: {e}")
        return {}

def fetch_kev_entries(cve_list):
    """Check if CVEs are listed in the CISA KEV database."""
    response = requests.get(KEV_API)
    
    try:
        kev_data = response.json()
        kev_cves = {entry["cveID"] for entry in kev_data.get("vulnerabilities", [])}
        return {cve: cve in kev_cves for cve in cve_list}
    except Exception as e:
        print(f"Error fetching KEV data: {e}")
        return {}

def fetch_nvd_data(cve_id):
    """Fetch NVD data for a specific CVE."""
    time.sleep(1)  # Basic rate limiting
    response = requests.get(f"{NVD_API_BASE}{cve_id}")

    try:
        data = response.json()
        cvss_score = data.get("result", {}).get("CVE_Items", [{}])[0].get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "N/A")
        return cvss_score
    except Exception as e:
        print(f"Error fetching NVD data for {cve_id}: {e}")
        return "N/A"

def scan_sboms(directory):
    """Scan multiple SBOM files for CVEs and check against KEV, EPSS, NVD, and ExploitDB."""
    results = []
    
    for sbom_file in Path(directory).glob("*.json"):
        print(f"Processing: {sbom_file}")
        if "cyclonedx" in sbom_file.name.lower():
            cve_list = extract_cves_from_cyclonedx(sbom_file)
        else:
            continue  # Skip unknown formats

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

def plot_charts(results):
    """Generate charts from the vulnerability scan results."""

    # Extract data for plotting
    epss_scores = [entry["EPSS_Score"] for entry in results if entry["EPSS_Score"] is not None]
    cvss_scores = [entry["CVSS_Score"] for entry in results if entry["CVSS_Score"] is not None]
    kev_counts = sum(1 for entry in results if entry["In_KEV"])

    # EPSS Score Distribution (Histogram)
    plt.figure(figsize=(10, 5))
    plt.hist(epss_scores, bins=10, color="blue", alpha=0.7, edgecolor="black")
    plt.xlabel("EPSS Score")
    plt.ylabel("Number of CVEs")
    plt.title("EPSS Score Distribution")
    plt.grid(True)
    plt.show()

    # CVSS Score Distribution (Bar Chart)
    plt.figure(figsize=(10, 5))
    plt.hist(cvss_scores, bins=np.arange(0, 10.5, 0.5), color="green", alpha=0.7, edgecolor="black")
    plt.xlabel("CVSS Score")
    plt.ylabel("Number of CVEs")
    plt.title("CVSS Score Distribution")
    plt.grid(True)
    plt.show()

    # KEV Pie Chart
    plt.figure(figsize=(6, 6))
    labels = ["In KEV", "Not in KEV"]
    sizes = [kev_counts, len(results) - kev_counts]
    colors = ["red", "gray"]
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors, startangle=140, shadow=True)
    plt.title("KEV Coverage")
    plt.show()

if __name__ == "__main__":
    sbom_dir = "./"
    report_file = "vulnerability_report.json"

    results = scan_sboms(sbom_dir)
    save_report(results, report_file)
    plot_charts(results)
