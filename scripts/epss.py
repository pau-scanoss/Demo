#just to test again
import requests
import json
import csv

# API Endpoints
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_epss_scores(cve_list):
    """Fetch EPSS scores for a list of CVEs."""
    try:
        cve_query = ",".join(cve_list)
        url = f"{EPSS_API}?cve={cve_query}"
        response = requests.get(url)
        data = response.json()
        return {item["cve"]: float(item["epss"]) for item in data.get("data", [])}
    except Exception as e:
        print(f"Error fetching EPSS scores: {e}")
        return {}

def fetch_kev_data():
    """Fetch KEV data from CISA's KEV database."""
    try:
        response = requests.get(KEV_API)
        kev_data = response.json()
        kev_results = {}
        for vuln in kev_data.get("vulnerabilities", []):
            cve = vuln.get("cveID")
            kev_results[cve] = {
                "Exploitability": vuln.get("knownExploitability", "Unverified"),
                "Date Added": vuln.get("dateAdded"),
            }
        return kev_results
    except Exception as e:
        print(f"Error fetching KEV data: {e}")
        return {}

def process_sbom(sbom_file):
    """Scan an SBOM file for CVEs and check against KEV, EPSS."""
    with open(sbom_file, "r") as f:
        sbom_data = json.load(f)

    cve_list = {vuln.get("id") for vuln in sbom_data.get("vulnerabilities", []) if vuln.get("id", "").startswith("CVE-")}
    epss_scores = fetch_epss_scores(cve_list)
    kev_results = fetch_kev_data()

    results = []
    for cve in cve_list:
        epss_score = epss_scores.get(cve, 0)
        risk_category = "High" if epss_score > 0.7 else "Medium" if epss_score > 0.3 else "Low"
        kev_entry = kev_results.get(cve, {"Exploitability": "Unverified", "Date Added": "Unknown"})

        results.append({
            "CVE": cve,
            "EPSS_Score": epss_score,
            "EPSS Risk": risk_category,
            "In_KEV": cve in kev_results,
            "KEV Exploitability": kev_entry["Exploitability"],
            "KEV Date Added": kev_entry["Date Added"],
        })

    return results

def save_results_to_csv(results, output_file="epss_kev_results.csv"):
    """Save the processed KEV and EPSS data to CSV."""
    keys = results[0].keys() if results else []
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

# Example usage
sbom_file = "sbom.json"
results = process_sbom(sbom_file)
save_results_to_csv(results)
