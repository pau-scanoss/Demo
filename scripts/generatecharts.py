import json
import pandas as pd
from tabulate import tabulate
import matplotlib.pyplot as plt

# Debugging function
def debug(msg):
    print(f"[DEBUG] {msg}")

# Load CycloneDX JSON
debug("Loading CycloneDX JSON file...")
with open("cycloneDX.json", "r") as file:
    data = json.load(file)
debug("JSON file loaded successfully.")

# Extract components and vulnerabilities
components = data.get("components", [])
vulnerabilities = data.get("vulnerabilities", [])
debug(f"Found {len(components)} components and {len(vulnerabilities)} vulnerabilities.")

# Process components for licenses, cryptographic algorithms, and metadata
license_data = []
crypto_data = []
component_metadata = []

debug("Processing components...")
for component in components:
    licenses = component.get("licenses", [])
    crypto_info = component.get("cryptography", [])
    
    # Process licenses
    for lic in licenses:
        license_data.append({
            "License ID": lic.get("license", {}).get("id", "Unknown"),
            "License Name": lic.get("license", {}).get("name", "Unknown"),
            "Copyright": lic.get("attribution", {}).get("text", "None"),
            "Obligations": lic.get("attribution", {}).get("obligations", "None")
        })
    
    # Process cryptographic algorithms
    for crypto in crypto_info:
        crypto_data.append({
            "Algorithm": crypto.get("algorithm", "Unknown"),
            "Strength": crypto.get("strength", "Unknown"),
            "Description": crypto.get("description", "None")
        })
    
    # Metadata for components
    component_metadata.append({
        "Name": component.get("name", "Unknown"),
        "Version": component.get("version", "Unknown"),
        "Publisher": component.get("publisher", "Unknown"),
        "Licenses": ", ".join([lic.get("license", {}).get("id", "Unknown") for lic in licenses])
    })

# Process vulnerabilities
debug("Processing vulnerabilities...")
vulnerability_data = []
for vuln in vulnerabilities:
    affected_components = []
    affects = vuln.get("affects", {})
    if isinstance(affects, dict):
        affected_components = [
            c.get("name", "Unknown") for c in affects.get("components", [])
        ]
    elif isinstance(affects, list):
        for affect in affects:
            if isinstance(affect, dict):
                affected_components.extend(
                    [c.get("name", "Unknown") for c in affect.get("components", [])]
                )
    vulnerability_data.append({
        "ID": vuln.get("id", "Unknown"),
        "Severity": vuln.get("ratings", [{}])[0].get("severity", "Unknown"),
        "Description": vuln.get("description", "No description available."),
        "Affected Components": ", ".join(affected_components) if affected_components else "Unknown"
    })

# Convert data to DataFrames
debug("Creating DataFrames...")
license_df = pd.DataFrame(license_data)
crypto_df = pd.DataFrame(crypto_data)
component_df = pd.DataFrame(component_metadata)
vuln_df = pd.DataFrame(vulnerability_data)

# Generate charts
debug("Generating charts...")
license_summary = license_df["License ID"].value_counts().reset_index()
license_summary.columns = ["License", "Count"]
license_chart = license_summary.head(10)

plt.figure(figsize=(8, 6))
license_chart.plot(kind="bar", x="License", y="Count", legend=False)
plt.title("Top Licenses in Components")
plt.xlabel("License")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("top_licenses.png")
debug("Saved 'top_licenses.png'.")

# Save detailed reports
debug("Saving detailed reports as artifacts...")
license_df.to_csv("detailed_licenses.csv", index=False)
crypto_df.to_csv("detailed_crypto.csv", index=False)
component_df.to_csv("detailed_components.csv", index=False)
vuln_df.to_csv("detailed_vulnerabilities.csv", index=False)

# Generate Markdown Summary
debug("Generating Markdown summary...")
markdown_lines = [
    "# SCANOSS SBOM Dashboard 📊",
    "\n## Summary\n",
    f"- Total Components: {len(components)}",
    f"- Total Vulnerabilities: {len(vulnerabilities)}",
    "\n## License Distribution (Top 10)\n",
    tabulate(license_summary.head(10), headers="keys", tablefmt="github"),
    "\n## Cryptographic Algorithms (Top 10)\n",
    tabulate(crypto_df.head(10), headers="keys", tablefmt="github") if not crypto_df.empty else "No cryptographic data available.\n",
    "\n## Vulnerabilities (Top 10)\n",
    tabulate(vuln_df.head(10), headers="keys", tablefmt="github") if not vuln_df.empty else "No vulnerabilities detected.\n",
    "\n## Repository Components (Top 10)\n",
    tabulate(component_df.head(10), headers="keys", tablefmt="github"),
    "\n## Additional Details\n",
    "- [Full License Data](./detailed_licenses.csv)",
    "- [Full Cryptographic Data](./detailed_crypto.csv)",
    "- [Full Component Data](./detailed_components.csv)",
    "- [Full Vulnerability Data](./detailed_vulnerabilities.csv)",
]

# Write Markdown Summary
with open("summary.md", "w") as f:
    f.write("\n".join(markdown_lines))
debug("Markdown summary saved as 'summary.md'.")

# Output truncated summary to stdout
print("\n".join(markdown_lines[:15] + ["..."]))
debug("Script execution completed successfully.")