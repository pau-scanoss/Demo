import json
import pandas as pd
from tabulate import tabulate
import matplotlib.pyplot as plt

# Load CycloneDX JSON
print("[DEBUG] Loading CycloneDX JSON file...")
with open("cycloneDX.json", "r") as file:
    data = json.load(file)
print("[DEBUG] JSON file loaded successfully.")

components = data.get("components", [])
vulnerabilities = data.get("vulnerabilities", [])

print(f"[DEBUG] Found {len(components)} components and {len(vulnerabilities)} vulnerabilities.")

# Data Containers
license_data = []
crypto_data = []
vulnerability_data = []
component_metadata = []
license_warnings = []
weak_crypto = []

# Helper function for license enrichment
def enrich_license_data(license_name):
    obligations = {
        "GPL-3.0-only": "Disclose source, include GPL license, retain copyright.",
        "LGPL-2.1-only": "Disclose source for modifications, allow linking without restrictions.",
        "Apache-2.0": "Notify, include LICENSE and NOTICE files.",
        "MIT": "Include copyright and license notice.",
        "BSD-3-Clause": "Retain copyright and license notices, no endorsement clauses.",
        "MPL-2.0": "Disclose source, include MPL license notice.",
        "SSPL-1.0": "Open source service requirements.",
        "Unknown": "N/A",
    }
    is_problematic = license_name in ["GPL-3.0-only", "LGPL-2.1-only", "SSPL-1.0"]
    return {
        "Obligations": obligations.get(license_name, "Custom license obligations."),
        "Problematic": is_problematic,
        "Full Text": f"https://spdx.org/licenses/{license_name}.html" if license_name != "Unknown" else "N/A",
    }

# Helper function for weak crypto detection
def is_weak_crypto(algorithm, strength):
    weak_algorithms = {
        "md5": "MD5 is vulnerable to collision attacks.",
        "sha1": "SHA-1 is deprecated due to vulnerabilities.",
        "des": "DES is outdated and insecure.",
        "3des": "3DES is considered weak and insecure.",
        "rsa": "RSA with less than 2048 bits is insecure.",
        "blowfish": "Blowfish is outdated; use AES instead.",
    }
    if algorithm.lower() in weak_algorithms:
        return {
            "Algorithm": algorithm,
            "Strength": strength,
            "Reason": weak_algorithms[algorithm.lower()],
            "Recommendation": "Use modern algorithms such as AES or SHA-256.",
        }
    return None

# Process Components
print("[DEBUG] Processing components...")
for component in components:
    licenses = component.get("licenses", [])
    license_names = [lic.get("license", {}).get("id", "Unknown") for lic in licenses]
    license_data.extend(license_names)

    component_metadata.append({
        "Name": component.get("name", "Unknown"),
        "Version": component.get("version", "Unknown"),
        "Publisher": component.get("publisher", "Unknown"),
        "Licenses": ", ".join(license_names) if license_names else "None",
    })

    for license_name in license_names:
        enriched = enrich_license_data(license_name)
        if enriched["Problematic"]:
            license_warnings.append({
                "License": license_name,
                "Obligations": enriched["Obligations"],
                "Full Text": enriched["Full Text"],
            })

# Process Vulnerabilities
print("[DEBUG] Processing vulnerabilities...")
for vuln in vulnerabilities:
    affects_data = vuln.get("affects", {})
    if isinstance(affects_data, list):
        affected_components_list = [comp.get("name", "Unknown") for comp in affects_data if isinstance(comp, dict)]
    elif isinstance(affects_data, dict):
        affected_components_list = [comp.get("name", "Unknown") for comp in affects_data.get("components", [])]
    else:
        affected_components_list = ["Unknown"]

    vulnerability_data.append({
        "ID": vuln.get("id", "Unknown"),
        "Severity": vuln.get("ratings", [{}])[0].get("severity", "Unknown"),
        "Description": vuln.get("description", "No description available."),
        "Affected Components": ", ".join(affected_components_list),
    })

# Process Crypto Data
print("[DEBUG] Processing cryptographic data...")
with open("crypto_results.txt", "r") as crypto_file:
    crypto_results = json.load(crypto_file)

for purl in crypto_results.get("purls", []):
    for algorithm in purl.get("algorithms", []):
        crypto_data.append({
            "Algorithm": algorithm.get("algorithm", "Unknown"),
            "Strength": algorithm.get("strength", "Unknown"),
        })
        weak = is_weak_crypto(algorithm.get("algorithm", ""), algorithm.get("strength", ""))
        if weak:
            weak_crypto.append(weak)

# Generate DataFrames
print("[DEBUG] Creating DataFrames...")
license_df = pd.DataFrame(license_data, columns=["License"])
crypto_df = pd.DataFrame(crypto_data)
vulnerability_df = pd.DataFrame(vulnerability_data)
component_df = pd.DataFrame(component_metadata)
warnings_df = pd.DataFrame(license_warnings)

# Generate Markdown Summary
print("[DEBUG] Generating Markdown summary...")
with open("summary.md", "w", encoding="utf-8") as f:
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")
    f.write(f"## Summary\n\n- **Total Components**: {len(components)}\n- **Total Vulnerabilities**: {len(vulnerabilities)}\n\n---\n\n")

    f.write("## License Distribution (Top 10)\n\n")
    license_summary = license_df["License"].value_counts().reset_index()
    license_summary.columns = ["License", "Count"]
    license_summary["Obligations"] = license_summary["License"].apply(lambda x: enrich_license_data(x)["Obligations"])
    license_summary["Full Text"] = license_summary["License"].apply(lambda x: enrich_license_data(x)["Full Text"])
    license_md = tabulate(license_summary.head(10).values, headers=["License", "Count", "Obligations", "Full Text"], tablefmt="github")
    f.write(license_md + "\n\n")

    f.write("## License Warnings ⚠️\n\n")
    warnings_md = tabulate(warnings_df.values, headers=["License", "Obligations", "Full Text"], tablefmt="github")
    f.write(warnings_md + "\n\n")

    f.write("## Crypto Analysis Results\n\n")
    if crypto_df.empty:
        f.write("No cryptographic data available.\n\n")
    else:
        crypto_md = tabulate(crypto_df.head(10).values, headers=crypto_df.columns, tablefmt="github")
        f.write(crypto_md + "\n\n")

    f.write("## Weak Cryptographic Algorithms ⚠️\n\n")
    if weak_crypto:
        weak_crypto_df = pd.DataFrame(weak_crypto)
        weak_crypto_md = tabulate(weak_crypto_df.values, headers=["Algorithm", "Strength", "Reason", "Recommendation"], tablefmt="github")
        f.write(weak_crypto_md + "\n\n")
    else:
        f.write("No weak cryptographic algorithms detected.\n\n")

    f.write("## Vulnerabilities (Top 10)\n\n")
    vuln_md = tabulate(vulnerability_df.head(10).values, headers=vulnerability_df.columns, tablefmt="github")
    f.write(vuln_md + "\n\n")

    f.write("## Repository Components (Top 10)\n\n")
    components_md = tabulate(component_df.head(10).values, headers=component_df.columns, tablefmt="github")
    f.write(components_md + "\n\n")

    f.write("## Notes:\n- Detailed reports are saved as artifacts and accessible via linked resources.\n\n")

print("[DEBUG] Markdown summary generated successfully.")