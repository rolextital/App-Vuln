# Software Vulnerability Scanner

A Python-based tool that scans installed applications on Windows systems, matches them against known vulnerabilities, and generates a comprehensive PDF report.

## Features

- 📊 Scans both traditionally installed applications and Microsoft Store apps
- 🔍 Matches software against known vendor and product databases
- 🔄 Version number detection and standardization
- 📝 Generates detailed vulnerability reports in PDF format
- 🎯 CVSS score-based vulnerability severity assessment
- 📈 Progress tracking with status bars
- 🧹 Intelligent string cleaning and matching

## Prerequisites

- Python 3.x
- Windows Operating System

## Required Packages

```
winreg (built-in)
pandas
requests
beautifulsoup4
reportlab
tqdm
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rolextital/App-Vuln
cd Vuln_Scan
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Required Files

The following CSV files are needed in the same directory as the script:
- `Combined_Vendors.csv`: List of known software vendors
- `Combined_Products.csv`: List of known software products
- `known_vendors.csv`: List of verified vendor names

## Usage

1. Run the main script:
```bash
python final.py
```

2. The script will:
   - Scan your system for installed applications
   - Create an initial `output.txt` with raw scan results
   - Process and standardize the data in `processed_output.txt`
   - Generate a comprehensive vulnerability report as PDF

## Output Files

- `output.txt`: Raw scan results
- `processed_output.txt`: Standardized application data
- `lower_rank_products.csv`: Secondary product matches for verification
- `vulnerability_report.pdf`: Final report with vulnerability assessment

## Report Contents

The vulnerability report includes:
- Executive summary with key statistics
- Detailed findings for each application
- CVSS scores and severity ratings
- Vulnerability descriptions and publication dates
- Color-coded severity indicators

## Functions Overview

### Main Components

- `check_and_install_packages()`: Verifies and installs required packages
- `list_store_apps()`: Scans Microsoft Store applications
- `foo()`: Scans registry for traditionally installed applications
- `process_apps()`: Processes and standardizes application data
- `search_cve()`: Searches for known vulnerabilities
- `VulnerabilityReport`: Handles PDF report generation

### Helper Functions

- `clean_string()`: Removes special characters and version numbers
- `standardize_name()`: Matches names against known databases
- `extract_version_numbers()`: Identifies version numbers in strings
- `calculate_match_score()`: Computes string similarity scores

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


## Acknowledgments

- CVE Details for vulnerability data
- ReportLab for PDF generation
- Beautiful Soup for web scraping

## Note

This tool is intended for security assessment purposes only. Please ensure you have proper authorization before scanning any systems.
