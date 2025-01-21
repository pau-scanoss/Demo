import json
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
from tabulate import tabulate

# Load the CycloneDX JSON file
print("[DEBUG] Loading CycloneDX JSON file...")
with open("cycloneDX.json", "r") as file:
    data = json.load(file)
print("[DEBUG] JSON file loaded successfully.")

# Extract relevant sections
components = data.get("components", [])
vulnerabilities = data.get("vulnerabilities", [])
print(f"[DEBUG] Found {len(components)} components and {len(vulnerabilities)} vulnerabilities.")

# Data containers
license_data = []
component_metadata = []
vulnerability_data = []
crypto_data = []

# Obligations and SPDX links
license_info = {
    "Apache-2.0": {
        "Obligations": "Must include NOTICE file and attribution.",
        "Link": "https://spdx.org/licenses/Apache-2.0.html"
    },
    "MIT": {
        "Obligations": "Attribution required.",
        "Link": "https://spdx.org/licenses/MIT.html"
    },
    "BSD-3-Clause": {
        "Obligations": "Attribution and NO endorsement clause.",
        "Link": "https://spdx.org/licenses/BSD-3-Clause.html"
    },
    "GPL-2.0-only": {
        "Obligations": "Must disclose source code and license.",
        "Link": "https://spdx.org/licenses/GPL-2.0-only.html"
    },
    "BSD-2-Clause": {
        "Obligations": "Attribution required.",
        "Link": "https://spdx.org/licenses/BSD-2-Clause.html"
    },
    "CC-BY-SA-3.0": {
        "Obligations": "Attribution and share-alike for derivatives.",
        "Link": "https://spdx.org/licenses/CC-BY-SA-3.0.html"
    },
    "SSPL-1.0": {
        "Obligations": "Must open source for cloud services.",
        "Link": "https://spdx.org/licenses/SSPL-1.0.html"
    },
    "Ruby": {
        "Obligations": "Attribution required.",
        "Link": "https://spdx.org/licenses/Ruby.html"
    },
    "MPL-2.0": {
        "Obligations": "Must disclose changes under same license.",
        "Link": "https://spdx.org/licenses/MPL-2.0.html"
    }
}

# Initialize license data for multiple result sets
consolidated_license_data = {}

# Process components for licenses and metadata
print("[DEBUG] Processing components...")
result_sets = [components]  # Add additional sources if needed, e.g., external_components
for result_set in result_sets:
    for component in result_set:
        licenses = component.get("licenses", [])
        for lic in licenses:
            license_id = lic.get("license", {}).get("id", "Unknown")
            # Consolidate license data
            if license_id not in consolidated_license_data:
                consolidated_license_data[license_id] = {
                    "Count": 0,
                    "Obligations": license_info.get(license_id, {}).get("Obligations", "Unknown"),
                    "Link": license_info.get(license_id, {}).get("Link", "-"),
                    "Copyrights": set()
                }
            consolidated_license_data[license_id]["Count"] += 1
            # Collect copyrights
            publisher = component.get("publisher", "Unknown")
            if publisher != "Unknown":
                consolidated_license_data[license_id]["Copyrights"].add(publisher)

        component_metadata.append({
            "Name": component.get("name", "Unknown"),
            "Publisher": component.get("publisher", "Unknown"),
            "Version": component.get("version", "Unknown"),
            "Licenses": ", ".join([lic.get("license", {}).get("id", "Unknown") for lic in licenses]),
            "Provenance": component.get("provenance", {}).get("country", "Unknown")
        })

        # Extract cryptographic data if available
        cryptos = component.get("cryptography", [])
        for crypto in cryptos:
            crypto_data.append({
                "Component": component.get("name", "Unknown"),
                "Algorithm": crypto.get("algorithm", "Unknown"),
                "Strength": crypto.get("strength", "Unknown"),
                "ECCN": crypto.get("eccn", "Unknown")
            })

# Process vulnerabilities
print("[DEBUG] Processing vulnerabilities...")
for vuln in vulnerabilities:
    severity = vuln.get("ratings", [{}])[0].get("severity", "Unknown")
    
    # Handle case where 'affects' might be a list instead of a dictionary
    affected_components = []
    affects = vuln.get("affects", [])
    if isinstance(affects, list):
        for affect in affects:
            components = affect.get("components", [])
            if isinstance(components, list):
                affected_components.extend([c.get("name", "Unknown") for c in components])

    vulnerability_data.append({
        "ID": vuln.get("id", "Unknown ID"),
        "Severity": severity,
        "Description": vuln.get("description", "No description provided"),
        "Fix Version": vuln.get("fix_version", "Unknown"),
        "CWEs": ", ".join(vuln.get("cwes", [])),
        "Affected Components": affected_components
    })
    print(f"[DEBUG] Processed vulnerability: {vuln.get('id', 'Unknown')} with severity: {severity}")

# Create DataFrames
print("[DEBUG] Creating DataFrames...")
component_df = pd.DataFrame(component_metadata)
vuln_df = pd.DataFrame(vulnerability_data)
crypto_df = pd.DataFrame(crypto_data)
print("[DEBUG] DataFrames created successfully.")

# Enhance license summary
print("[DEBUG] Enhancing license summary...")
enhanced_license_summary = []
for license_id, details in consolidated_license_data.items():
    enhanced_license_summary.append([
        license_id,
        details["Count"],
        details["Obligations"],
        details["Link"],
        ", ".join(details["Copyrights"]) or "None"
    ])

enhanced_license_md = tabulate(
    enhanced_license_summary,
    headers=["License", "Count", "Obligations", "Full Text", "Copyrights / Attribution"],
    tablefmt="github"
)
print("[DEBUG] Enhanced license summary generated.")

# Generate charts
print("[DEBUG] Generating charts...")
license_df = pd.DataFrame(enhanced_license_summary, columns=["License", "Count", "Obligations", "Full Text", "Copyrights / Attribution"])
license_df.head(10).plot(kind="bar", x="License", y="Count", legend=False)
plt.title("Top Licenses in Components")
plt.xlabel("License")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("top_licenses.png")
print("[DEBUG] Saved 'top_licenses.png'.")
plt.close()

plt.figure(figsize=(8, 6))
vuln_df["Severity"].value_counts().plot(kind="bar", legend=False, color="orange")
plt.title("Vulnerabilities by Severity")
plt.xlabel("Severity")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("vulnerability_severity.png")
print("[DEBUG] Saved 'vulnerability_severity.png'.")
plt.close()

# Save component metadata to CSV
print("[DEBUG] Saving component metadata to CSV...")
component_df.to_csv("component_metadata.csv", index=False)
print("[DEBUG] Saved 'component_metadata.csv'.")

# Generate Markdown summary
print("[DEBUG] Generating Markdown summary...")
with open("summary.md", "w") as f:
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")
    f.write("## Enhanced License Distribution\n")
    f.write(enhanced_license_md + "\n\n")

    f.write("## Cryptographic Algorithm Usage (Top 10)\n")
    if not crypto_df.empty:
        crypto_md = tabulate(
            crypto_df.head(10).values,
            headers=crypto_df.columns,
            tablefmt="github"
        )
        f.write(crypto_md + "\n\n")
    else:
        f.write("No cryptographic data available.\n\n")

    f.write("## Repository Component Metadata\n")
    components_md = tabulate(component_df.head(10).values, headers=component_df.columns, tablefmt="github")
    f.write(components_md + "\n\n")

    if not vuln_df.empty:
        total_vulnerabilities = vuln_df.shape[0]
        f.write(f"## Vulnerability Summary\n- {total_vulnerabilities} vulnerabilities detected.\n")
        f.write("- Detailed vulnerability breakdown by severity:\n\n")
        vuln_details_md = tabulate(
            vuln_df["Severity"].value_counts().reset_index().values,
            headers=["Severity", "Count"],
            tablefmt="github"
        )
        f.write(vuln_details_md + "\n\n")

print("[DEBUG] Markdown summary generated successfully.")
