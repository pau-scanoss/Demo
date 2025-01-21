import os
import json
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
from tabulate import tabulate

# Create the artifacts directory if it doesn't exist
artifacts_dir = "artifacts"
os.makedirs(artifacts_dir, exist_ok=True)

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
cryptographic_data = []
consolidated_license_data = {}

# License details with obligations, links, etc.
license_info = {
    "Apache-2.0": {
        "Obligations": "Must include NOTICE file and attribution.",
        "Link": "https://spdx.org/licenses/Apache-2.0.html"
    },
    "MIT": {
        "Obligations": "Attribution required.",
        "Link": "https://spdx.org/licenses/MIT.html"
    },
    # Add more licenses as needed...
}

# Process components
print("[DEBUG] Processing components...")
for component in components:
    licenses = component.get("licenses", [])
    license_names = [lic.get("license", {}).get("id", "Unknown") for lic in licenses]
    license_data.extend(license_names)

    for lic in license_names:
        if lic not in consolidated_license_data:
            consolidated_license_data[lic] = {
                "Count": 0,
                "Obligations": license_info.get(lic, {}).get("Obligations", "Unknown"),
                "Link": license_info.get(lic, {}).get("Link", "Unknown"),
                "Copyrights": set()
            }
        consolidated_license_data[lic]["Count"] += 1

    component_metadata.append({
        "Name": component.get("name", "Unknown"),
        "Publisher": component.get("publisher", "Unknown"),
        "Version": component.get("version", "Unknown"),
        "Licenses": ", ".join(license_names) if license_names else "None",
    })

# Process vulnerabilities
print("[DEBUG] Processing vulnerabilities...")
for vuln in vulnerabilities:
    vuln_id = vuln.get("id", "Unknown")
    severity = vuln.get("ratings", [{}])[0].get("severity", "Unknown")
    description = vuln.get("description", "No description provided.")
    fix_version = vuln.get("advisory", {}).get("fixed_version", "Unknown")
    cwes = ", ".join(vuln.get("cwes", []))

    # Ensure 'affects' and 'components' are properly handled
    affected_components_list = vuln.get("affects", {}).get("components", [])
    if isinstance(affected_components_list, list):
        affected_components = ", ".join([c.get("name", "Unknown") for c in affected_components_list if isinstance(c, dict)])
    else:
        affected_components = "Unknown"

    vulnerability_data.append({
        "ID": vuln_id,
        "Severity": severity,
        "Description": description,
        "Fix Version": fix_version,
        "CWEs": cwes,
        "Affected Components": affected_components,
    })
    print(f"[DEBUG] Processed vulnerability: {vuln_id} with severity: {severity}")

# Create DataFrames
print("[DEBUG] Creating DataFrames...")
license_df = pd.DataFrame(license_data, columns=["License"])
component_df = pd.DataFrame(component_metadata)
vuln_df = pd.DataFrame(vulnerability_data)
crypto_df = pd.DataFrame(cryptographic_data, columns=["Component", "Algorithm", "Strength (bits)", "ECCN Code"])
print("[DEBUG] DataFrames created successfully.")

# Enhance License Summary
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

# Generate Charts
print("[DEBUG] Generating charts...")
license_chart_path = os.path.join(artifacts_dir, "top_licenses.png")
license_df["License"].value_counts().head(10).plot(kind="bar")
plt.title("Top Licenses in Components")
plt.xlabel("License")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(license_chart_path)
print(f"[DEBUG] Saved '{license_chart_path}'.")
plt.close()

vulnerability_chart_path = os.path.join(artifacts_dir, "vulnerability_severity.png")
vuln_df["Severity"].value_counts().plot(kind="bar", color="orange")
plt.title("Vulnerabilities by Severity")
plt.xlabel("Severity")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(vulnerability_chart_path)
print(f"[DEBUG] Saved '{vulnerability_chart_path}'.")
plt.close()

# Save component metadata to CSV
component_metadata_path = os.path.join(artifacts_dir, "component_metadata.csv")
print("[DEBUG] Saving component metadata to CSV...")
component_df.to_csv(component_metadata_path, index=False)
print(f"[DEBUG] Saved '{component_metadata_path}'.")

# Save detailed vulnerabilities to CSV
vulnerability_metadata_path = os.path.join(artifacts_dir, "vulnerability_metadata.csv")
print("[DEBUG] Saving vulnerability details to CSV...")
vuln_df.to_csv(vulnerability_metadata_path, index=False)
print(f"[DEBUG] Saved '{vulnerability_metadata_path}'.")

# Generate Markdown summary
markdown_path = os.path.join(artifacts_dir, "summary.md")
print("[DEBUG] Generating detailed Markdown summary...")
with open(markdown_path, "w") as f:
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")

    # License Summary
    f.write("## Enhanced License Distribution\n")
    f.write(enhanced_license_md + "\n\n")

    # Cryptographic Modules
    f.write("## Cryptographic Algorithm Usage\n")
    if not crypto_df.empty:
        crypto_md = tabulate(
            crypto_df.values,
            headers=crypto_df.columns,
            tablefmt="github"
        )
        f.write(crypto_md + "\n\n")
    else:
        f.write("No cryptographic data available.\n\n")

    # Vulnerability Summary
    f.write("## Vulnerability Summary\n")
    if not vuln_df.empty:
        total_vulnerabilities = vuln_df.shape[0]
        f.write(f"- Total vulnerabilities detected: **{total_vulnerabilities}**\n")
        f.write("- Breakdown by severity:\n\n")
        severity_md = tabulate(
            vuln_df["Severity"].value_counts().reset_index().values,
            headers=["Severity", "Count"],
            tablefmt="github"
        )
        f.write(severity_md + "\n\n")

        f.write("### Detailed Vulnerabilities\n")
        vuln_details_md = tabulate(
            vuln_df[["ID", "Severity", "Description", "Fix Version", "CWEs", "Affected Components"]].values,
            headers=["Vulnerability ID", "Severity", "Description", "Fix Version", "CWEs", "Affected Components"],
            tablefmt="github"
        )
        f.write(vuln_details_md + "\n\n")
    else:
        f.write("No vulnerabilities detected.\n\n")

    # Additional Notes
    f.write("## Notes\n")
    f.write("- Full SBOM details are available in the uploaded artifact.\n")
    f.write("- Ensure compliance with license obligations and address vulnerabilities promptly.\n")

print(f"[DEBUG] Detailed Markdown summary saved as '{markdown_path}'.")
