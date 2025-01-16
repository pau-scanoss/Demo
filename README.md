# Demo
SCANOSS GH Demo
# SCANOSS GitHub Action Demo

This repository demonstrates how to integrate [SCANOSS](https://www.scanoss.com) into your GitHub Actions workflows for automated software composition analysis (SCA). SCANOSS scans your project’s source code to identify open-source components, detect vulnerabilities, and ensure license compliance, helping your team maintain secure and compliant codebases.

---

## Features

- **Automated Scanning**: Trigger SCANOSS analysis on every push or pull request.
- **SBOM Generation**: Automatically generate a Software Bill of Materials (SBOM) in SPDX or CycloneDX format.
- **License Compliance**: Detect open-source licenses and ensure compatibility with your project's licensing requirements.
- **Vulnerability Detection**: Identify and assess vulnerabilities in declared and undeclared dependencies.

---

## Prerequisites

- **GitHub Repository**: A repository where you want to set up the SCANOSS GitHub Action.
- **SCANOSS API Key**: Obtain an API key from your [SCANOSS account](https://www.scanoss.com).
- **Configured Workflow File**: A `.yml` file in the `.github/workflows` directory of your repository.



---

## Usage

### Triggering the Action
- Push code to the `main` branch:
  ```bash
  git add .
  git commit -m "Your commit message"
  git push origin main



## Viewing Results

1. Go to the **Actions** tab in your repository.
2. Select the **SCANOSS Scan** workflow run.
3. View detailed logs and download the generated SBOM from the **Artifacts** section.

---

## Checks Performed

When code is checked in, the following checks are executed:

1. **Dependency Identification**:
   - Detects all open-source libraries and frameworks used in the project, including undeclared components.

2. **License Checks**:
   - Identifies the licenses of each component (e.g., MIT, GPL, Apache 2.0).
   - Flags license incompatibilities or risks based on the project’s compliance policies.

3. **Vulnerability Assessment**:
   - Matches identified dependencies with databases like NVD, OSV, and GitHub Advisories to detect known vulnerabilities (CVEs).
   - Outputs vulnerability details, including severity and recommended remediation.

4. **Cryptographic Analysis**:
   - Detects cryptographic algorithms in the code.
   - Evaluates the strength and compliance of algorithms with security standards.

5. **Provenance Tracking**:
   - Tracks the origin, authorship, and geographical location of code components for supply chain transparency.

---

## Output

The SCANOSS GitHub Action produces:
- **SBOM File**: A Software Bill of Materials in the specified format (e.g., SPDX, CycloneDX).
- **Detailed Logs**: Workflow logs provide insights into detected licenses, vulnerabilities, and compliance issues.

---

## Customization

- **Source Directory**: Modify the `source-dir` parameter to specify a subdirectory to scan.
- **Output Format**: Change the `output-format` parameter to generate SBOMs in different formats (e.g., `cycloneDx`).
- **Branch Triggers**: Adjust the `on` section of the workflow to trigger scans on specific branches or events.

---

## Troubleshooting

- **Missing API Key**: Ensure your SCANOSS API key is correctly configured as a GitHub secret.
- **Permission Issues**: Verify that the GitHub Actions runner has the necessary permissions to read/write files in your repository.
- **Incorrect Parameters**: Double-check the `source-dir` and `output-file` paths in the workflow configuration.

---

## Learn More

- [SCANOSS Documentation](https://docs.scanoss.com)
- [GitHub Actions Guide](https://docs.github.com/actions)
- [SPDX Specification](https://spdx.dev)
- [CycloneDX Specification](https://cyclonedx.org)
---

## Setup

### 1. Add Your SCANOSS API Key
Store your SCANOSS API key as a GitHub secret:
1. Go to your repository on GitHub.
2. Navigate to **Settings** > **Secrets and variables** > **Actions** > **New repository secret**.
3. Add a new secret with the name `SCANOSS_API_KEY` and paste your API key.

### 2. Create the GitHub Actions Workflow
Add a `.yml` file to your repository under `.github/workflows/scanoss.yml`:

```yaml
name: SCANOSS Scan

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  scanoss:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run SCANOSS scan
        uses: scanoss/scanoss-action@v1
        with:
          api-key: ${{ secrets.SCANOSS_API_KEY }}
          source-dir: . # Directory to scan
          output-format: clonedx # Options: spdxlite, cyclonedx, etc.
          output-file: scanoss_sbom.json # Name of the generated SBOM file

      - name: Upload SBOM Artifact
        uses: actions/upload-artifact@v3
        with:
          name: SCANOSS-SBOM
          path: scanoss_sbom.json
