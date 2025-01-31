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
NVD_RATE_LIMIT = 6  # 6 requests per 30 seconds
NVD_SLEEP_TIME = 30  # Sleep if rate limit exceeded

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

def fetch_nvd_data(cve_id, retries=3):
    """Fetch NVD CVSS data with error handling and rate-limiting."""
    url = f"{NVD_API_BASE}{cve_id}"

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=10)

            if response.status_code == 429:
                print(f"NVD API rate limit exceeded. Sleeping for {NVD_SLEEP_TIME} seconds...")
                time.sleep(NVD_SLEEP_TIME)
                continue  

            if response.status_code != 200:
                print(f"Error fetching NVD data for {cve_id}: HTTP {response.status_code}")
                return "N/A"

            data = response.json()
            if not data:
                print(f"Empty response for {cve_id} from NVD API.")
                return "N/A"

            cve_items = data.get("result", {}).get("CVE_Items", [])
            if cve_items:
                impact_data = cve_items[0].get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
                return impact_data.get("baseScore", "N/A")

            return "N/A"

        except requests.exceptions.RequestException as e:
            print(f"Request error for {cve_id}: {e}")
            time.sleep(5)  

    return "N/A"  

def scan_sboms(directory):
    """Scan multiple SBOM files for CVEs and check against KEV, EPSS, NVD, and ExploitDB."""
    results = []
    
    for sbom_file in Path(directory).glob("*.json"):
        print(f"Processing: {sbom_file}")
        if "cyclonedx" in sbom_file.name.lower():
            cve_list = extract_cves_from_cyclonedx(sbom_file)
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

if __name__ == "__main__":
    sbom_dir = "./"  
    report_file = "vulnerability_report.json"

    results = scan_sboms(sbom_dir)
    save_report(results, report_file)
