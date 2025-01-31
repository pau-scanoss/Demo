import json
import matplotlib.pyplot as plt
import numpy as np

# Load processed vulnerability data
with open("vulnerability_report.json", "r") as file:
    results = json.load(file)

# Extract data for plotting
epss_scores = [entry["EPSS_Score"] for entry in results if entry["EPSS_Score"] is not None]
cvss_scores = [entry["CVSS_Score"] for entry in results if entry["CVSS_Score"] is not None]
kev_counts = sum(1 for entry in results if entry["In_KEV"])

# Ensure summary.md exists before appending
summary_file = "summary.md"
if not os.path.exists(summary_file):
    with open(summary_file, "w") as f:
        f.write("# 📊 Vulnerability Scan Summary\n\n")

# Append Chart Summary to summary.md
with open(summary_file, "a") as summary:
    summary.write("\n## 📈 Charts Summary\n")
    summary.write(f"- 🛡️ **Total KEV CVEs:** {kev_counts}\n")
    if epss_scores:
        summary.write(f"- 📉 **Average EPSS Score:** {np.mean(epss_scores):.2f}\n")
    if cvss_scores:
        summary.write(f"- 💣 **Average CVSS Score:** {np.mean(cvss_scores):.1f}\n")

print("✅ Chart insights appended to summary.md")

# Generate EPSS Score Distribution
plt.figure(figsize=(10, 5))
plt.hist(epss_scores, bins=10, color="blue", alpha=0.7, edgecolor="black")
plt.xlabel("EPSS Score")
plt.ylabel("Number of CVEs")
plt.title("EPSS Score Distribution")
plt.grid(True)
plt.savefig("charts/epss_distribution.png")
plt.close()

# Generate CVSS Score Distribution
plt.figure(figsize=(10, 5))
plt.hist(cvss_scores, bins=np.arange(0, 10.5, 0.5), color="green", alpha=0.7, edgecolor="black")
plt.xlabel("CVSS Score")
plt.ylabel("Number of CVEs")
plt.title("CVSS Score Distribution")
plt.grid(True)
plt.savefig("charts/cvss_distribution.png")
plt.close()

# Generate KEV Coverage Pie Chart
plt.figure(figsize=(6, 6))
labels = ["In KEV", "Not in KEV"]
sizes = [kev_counts, len(results) - kev_counts]
colors = ["red", "gray"]
plt.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors, startangle=140, shadow=True)
plt.title("KEV Coverage")
plt.savefig("charts/kev_pie_chart.png")
plt.close()

print("📊 Charts generated and saved in 'charts' directory.")
