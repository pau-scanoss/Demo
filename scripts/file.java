import json
import pandas as pd
from tabulate import tabulate

# Load JSON data with error handling
def load_json(file_path):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return {}
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON format in file: {file_path}")
        return {}

# Load data
print("[DEBUG] Loading CycloneDX JSON file...")
sbom_data = load_json("cycloneDX.json")
print("[DEBUG] Loading crypto results...")
crypto_data = load_json("crypto_results.txt")

# Containers for data
components = sbom_data.get("components", [])
vulnerabilities = sbom_data.get("vulnerabilities", [])
weak_crypto = []
critical_vulnerabilities = []

# Weak crypto mappings
weak_crypto_recommendations = {
    "des": {"Status": "Weak", "Recommendation": "Use AES with 256-bit keys."},
    "md5": {"Status": "Weak", "Recommendation": "Use SHA-256 or SHA-3."},
    "sha1": {"Status": "Weak", "Recommendation": "Use SHA-256 or SHA-3."},
    "rsa": {"Status": "Weak", "Recommendation": "Use ECC or RSA with 2048-bit keys."},
    "blowfish": {"Status": "Weak", "Recommendation": "Use AES with 256-bit keys."},
    "tdes": {"Status": "Weak", "Recommendation": "Use AES with 256-bit keys."},
    "rc4": {"Status": "Weak", "Recommendation": "Use AES-GCM or AES-CCM."},
    "diffiehellman": {"Status": "Weak", "Recommendation": "Use ECDH or Diffie-Hellman with 2048-bit keys."},
}

# Process cryptographic algorithms
print("[DEBUG] Processing cryptographic data...")
for purl_entry in crypto_data.get("purls", []):
    for algo_entry in purl_entry.get("algorithms", []):
        algo_name = algo_entry.get("algorithm", "Unknown").lower()
        algo_strength = algo_entry.get("strength", "Unknown")
        if algo_name in weak_crypto_recommendations:
            status = weak_crypto_recommendations[algo_name]["Status"]
            recommendation = weak_crypto_recommendations[algo_name]["Recommendation"]
        else:
            status = "Strong"
            recommendation = "No action required."

        # Append to weak_crypto list
        weak_crypto.append({
            "Algorithm": algo_name.upper(),
            "Strength": algo_strength,
            "Status": status,
            "Recommendation": recommendation
        })

# Process vulnerabilities
print("[DEBUG] Processing vulnerabilities...")
for vuln in vulnerabilities:
    severity = vuln.get("ratings", [{}])[0].get("severity", "Unknown").lower()
    if severity == "critical":
        affects = vuln.get("affects", [])
        affected_components = []
        if isinstance(affects, list):
            affected_components = [
                comp.get("name", "Unknown") if isinstance(comp, dict) else "Unknown"
                for comp in affects
            ]
        elif isinstance(affects, dict):
            affected_components = [
                comp.get("name", "Unknown")
                for comp in affects.get("components", [])
            ]

        critical_vulnerabilities.append({
            "ID": vuln.get("id", "Unknown"),
            "Description": vuln.get("description", "No description available."),
            "Affected Components": ", ".join(affected_components)
        })

# Generate Markdown Summary
print("[DEBUG] Generating Markdown summary...")
with open("summary.md", "w", encoding="utf-8") as f:
    # Key Highlights
    f.write("# SCANOSS SBOM Dashboard 📊\n\n")
    f.write("## Key Highlights\n\n")
    f.write(f"- **Total Components**: {len(components)}\n")
    f.write(f"- **Total Vulnerabilities**: {len(vulnerabilities)}\n")
    f.write(f"- **Critical Vulnerabilities**: {len(critical_vulnerabilities)}\n")
    f.write(f"- **Weak Cryptographic Algorithms**: {len([c for c in weak_crypto if c['Status'] == 'Weak'])}\n\n")
    f.write("---\n\n")

    # Cryptographic Analysis
    f.write("## Cryptographic Analysis Results\n\n")
    if weak_crypto:
        crypto_df = pd.DataFrame(weak_crypto)
        crypto_md = tabulate(crypto_df, headers="keys", tablefmt="github", showindex=False)
        f.write(crypto_md + "\n\n")
    else:
        f.write("No cryptographic analysis data available.\n\n")

    # Vulnerabilities
    f.write("## Critical Vulnerabilities (Top 10)\n\n")
    if critical_vulnerabilities:
        critical_vuln_df = pd.DataFrame(critical_vulnerabilities)
        critical_vuln_md = tabulate(critical_vuln_df.head(10), headers="keys", tablefmt="github", showindex=False)
        f.write(critical_vuln_md + "\n\n")
    else:
        f.write("No critical vulnerabilities found.\n\n")

    # Placeholder for License Analysis
    f.write("## License Analysis\n\n")
    f.write("(License analysis data would be included here.)\n\n")

print("[DEBUG] Markdown summary generated successfully.")
