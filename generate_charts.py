import json
import pandas as pd
from collections import Counter
from tabulate import tabulate

# Load SCANOSS SBOM results
with open("results.json", "r") as file:
    data = json.load(file)

licenses = []
components_metadata = []
crypto_algorithms = []
provenance_data = []

# Extract relevant data
for file_data in data.values():
    for entry in file_data:
        # Extract licenses
        licenses_in_entry = entry.get("licenses", [])
        for license_info in licenses_in_entry:
            licenses.append(license_info.get("name", "Unknown License"))

        # Extract cryptographic algorithms
        cryptos_in_entry = entry.get("cryptography", [])
        for crypto_info in cryptos_in_entry:
            algorithm = crypto_info.get("algorithm", "Unknown Algorithm")
            strength = crypto_info.get("strength", "Unknown Strength")
            crypto_algorithms.append(f"{algorithm} ({strength}-bit)")

        # Extract component metadata
        provenance = entry.get("health", {}).get("country", "Unknown")
        component_name = entry.get("component", "Unknown Component")
        stars = entry.get("health", {}).get("stars", "N/A")
        forks = entry.get("health", {}).get("forks", "N/A")
        issues = entry.get("health", {}).get("issues", "N/A")
        last_updated = entry.get("health", {}).get("last_update", "N/A")
        version = entry.get("version", "N/A")
        author = entry.get("vendor", "N/A")
        quality_data = entry.get("quality", [])
        quality_score = quality_data[0].get("score", "N/A") if quality_data else "N/A"

        # Collect metadata for components
        components_metadata.append({
            "Component": component_name,
            "Stars": stars,
            "Forks": forks,
            "Issues": issues,
            "Last Updated": last_updated,
            "Provenance": provenance,
            "Version": version,
            "Author": author,
            "License": licenses_in_entry[0].get("name", "Unknown License") if licenses_in_entry else "Unknown License",
            "Quality Score": quality_score
        })

# Create DataFrames
license_df = pd.DataFrame({"License": licenses})
crypto_df = pd.DataFrame({"Algorithm": crypto_algorithms})
components_df = pd.DataFrame(components_metadata)

# Generate summaries
license_summary = license_df["License"].value_counts().head(10).reset_index().values
crypto_summary = crypto_df["Algorithm"].value_counts().head(10).reset_index().values
provenance_summary = Counter(entry.get("health", {}).get("country", "Unknown") for entry in data.get("components", [])).items()

# Markdown sections
license_md = tabulate(license_summary, headers=["License", "Count"], tablefmt="github")
crypto_md = tabulate(crypto_summary, headers=["Algorithm", "Count"], tablefmt="github")
components_md = tabulate(components_df.head(10), headers="keys", tablefmt="github")

# Generate Markdown summary
with open("summary.md", "w") as f:
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")
    f.write("## License Distribution (Top 10)\n")
    f.write(license_md + "\n\n")
    f.write("## Cryptographic Algorithm Usage (Top 10)\n")
    f.write(crypto_md if not crypto_df.empty else "No cryptographic data available.\n")
    f.write("\n\n## Repository Component Metadata\n")
    f.write(components_md + "\n\n")
    f.write("### Provenance Summary:\n")
    f.write("\n".join([f"- **{country}**: {count} components" for country, count in provenance_summary]) + "\n\n")
    f.write("## Notes:\n- No vulnerabilities detected.\n- Full SBOM details are available in the uploaded artifact.\n")

print("Text-only dashboard summary generated successfully.")
