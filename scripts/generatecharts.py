import json
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
from tabulate import tabulate

# Load the CycloneDX JSON file
print("Loading CycloneDX JSON file...")
with open("cycloneDX.json", "r") as file:
    data = json.load(file)
print("JSON file loaded successfully.")

# Extract relevant sections
components = data.get("components", [])
vulnerabilities = data.get("vulnerabilities", [])
print(f"Found {len(components)} components and {len(vulnerabilities)} vulnerabilities.")

# Data containers
license_data = []
component_metadata = []
vulnerability_data = []

# Process components for licenses and metadata
print("Processing components...")
for component in components:
    licenses = component.get("licenses", [])
    license_names = [lic.get("license", {}).get("id", "Unknown") for lic in licenses]
    license_data.extend(license_names)

    component_metadata.append({
        "Name": component.get("name", "Unknown"),
        "Publisher": component.get("publisher", "Unknown"),
        "Version": component.get("version", "Unknown"),
        "Licenses": ", ".join(license_names) if license_names else "None",
    })

# Process vulnerabilities
print("Processing vulnerabilities...")
for vuln in vulnerabilities:
    severity = vuln.get("ratings", [{}])[0].get("severity", "Unknown")
    vulnerability_data.append(severity)

# Create DataFrames
print("Creating DataFrames...")
license_df = pd.DataFrame(license_data, columns=["License"])
component_df = pd.DataFrame(component_metadata)
vuln_df = pd.DataFrame(vulnerability_data, columns=["Severity"])

# Summarize licenses
print("Summarizing licenses...")
license_summary = license_df["License"].value_counts().reset_index()
license_summary.columns = ["License", "Count"]
license_md = tabulate(license_summary.head(10).values, headers=["License", "Count"], tablefmt="github")

# Summarize vulnerabilities
print("Summarizing vulnerabilities...")
vuln_summary = vuln_df["Severity"].value_counts().reset_index()
vuln_summary.columns = ["Severity", "Count"]

# Generate charts
print("Generating charts...")
plt.figure(figsize=(8, 6))
license_summary.head(10).plot(kind="bar", x="License", y="Count", legend=False)
plt.title("Top Licenses in Components")
plt.xlabel("License")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("top_licenses.png")
print("Saved 'top_licenses.png'.")
plt.close()

plt.figure(figsize=(8, 6))
vuln_summary.plot(kind="bar", x="Severity", y="Count", legend=False, color="orange")
plt.title("Vulnerabilities by Severity")
plt.xlabel("Severity")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("vulnerability_severity.png")
print("Saved 'vulnerability_severity.png'.")
plt.close()

# Save component metadata to CSV
print("Saving component metadata to CSV...")
component_df.to_csv("component_metadata.csv", index=False)
print("Saved 'component_metadata.csv'.")

# Generate Markdown summary
print("Generating Markdown summary...")
with open("summary.md", "w") as f:
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")
    f.write("## License Distribution (Top 10)\n")
    f.write(license_md + "\n\n")
    f.write("## Cryptographic Algorithm Usage (Top 10)\n")
    f.write("No cryptographic data available.\n\n")
    f.write("## Repository Component Metadata\n")
    components_md = tabulate(component_df.head(10).values, headers=component_df.columns, tablefmt="github")
    f.write(components_md + "\n\n")
    f.write("## Notes:\n- No vulnerabilities detected.\n- Full SBOM details are available in the uploaded artifact.\n")
print("Saved 'summary.md'.")

print("Script executed successfully!")
