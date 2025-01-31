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

# EPSS Score Distribution
plt.figure(figsize=(10, 5))
plt.hist(epss_scores, bins=10, color="blue", alpha=0.7, edgecolor="black")
plt.xlabel("EPSS Score")
plt.ylabel("Number of CVEs")
plt.title("EPSS Score Distribution")
plt.grid(True)
plt.savefig("charts/epss_distribution.png")
plt.close()

# CVSS Score Distribution
plt.figure(figsize=(10, 5))
plt.hist(cvss_scores, bins=np.arange(0, 10.5, 0.5), color="green", alpha=0.7, edgecolor="black")
plt.xlabel("CVSS Score")
plt.ylabel("Number of CVEs")
plt.title("CVSS Score Distribution")
plt.grid(True)
plt.savefig("charts/cvss_distribution.png")
plt.close()

# KEV Pie Chart
plt.figure(figsize=(6, 6))
labels = ["In KEV", "Not in KEV"]
sizes = [kev_counts, len(results) - kev_counts]
colors = ["red", "gray"]
plt.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors, startangle=140, shadow=True)
plt.title("KEV Coverage")
plt.savefig("charts/kev_pie_chart.png")
plt.close()

print("Charts saved in the 'charts' directory.")
