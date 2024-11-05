import subprocess
import sys  # Ensure csv is imported as you pointed out
from tqdm import tqdm
# List of required packages
required_packages = [
    'winreg',  # Built-in, no installation needed
    'pandas',
    'requests',
    'beautifulsoup4',
    'reportlab',
    'tqdm'
]

def install(package):
    """Install the package using pip."""
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

def check_and_install_package(package_name):
    try:
        __import__(str(package_name))
        return f"{package_name} is already installed."
    except ImportError:
        subprocess.run(
            ["pip", "install", package_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return f"{package_name} has been installed."

def check_and_install_packages(packages):
    with tqdm(total=len(packages), desc="Checking packages", ncols=100) as pbar:
        for package in packages:
            check_and_install_package(package)
            pbar.update(1)
    print("")  # Line gap after the progress bar

def main():
    required_packages = ["winreg", "pandas", "requests", "beautifulsoup4", "reportlab", "tqdm"]
    
    # Step 1: Check and install packages
    check_and_install_packages(required_packages)
    
if __name__ == "__main__":
    # Ensure the main function runs only once
    main()
    
import winreg
import json
import re
import pandas as pd
import requests
import csv
from bs4 import BeautifulSoup
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from pathlib import Path
from datetime import datetime

# Define the base directory relative to the script's location
base_dir = Path(__file__).parent

def clean_string(input_str):
    """Cleans the input string by removing special characters and version numbers."""
    cleaned_str = re.sub(r'\b(v?[\d]+(\.\d+)+)\b', '', input_str)
    cleaned_str = re.sub(r'[^a-zA-Z0-9\s]', '', cleaned_str)
    return cleaned_str.strip()

def standardize_name(name, list_to_match):
    """Standardizes the name by checking it against the provided list."""
    for valid_name in list_to_match:
        if name.lower() in valid_name.lower():
            return valid_name
    return name

def load_csv_data(vendor_csv_path, product_csv_path):
    """Loads the vendor and product data from CSV files."""
    vendors = pd.read_csv(vendor_csv_path)['Vendor Name'].tolist()
    products = pd.read_csv(product_csv_path)['Product Name'].tolist()
    return vendors, products

def list_store_apps():
    store_apps_list = []
    try:
        output = subprocess.check_output(["powershell", "Get-AppxPackage | ConvertTo-Json"], stderr=subprocess.STDOUT)
        store_apps = json.loads(output)

        for app in store_apps:
            name = clean_string(app.get("Name", "Unknown"))
            version = app.get("Version", "Unknown")
            publisher = clean_string(app.get("Publisher", "Unknown"))

            store_apps_list.append({
                "name": name,
                "version": version,
                "publisher": publisher
            })
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving Microsoft Store apps: {e.output.decode()}")
    
    return store_apps_list

def foo(hive, flag):
    aReg = winreg.ConnectRegistry(None, hive)
    aKey = winreg.OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | flag)

    count_subkey = winreg.QueryInfoKey(aKey)[0]

    software_list = []

    for i in range(count_subkey):
        software = {}
        try:
            asubkey_name = winreg.EnumKey(aKey, i)
            asubkey = winreg.OpenKey(aKey, asubkey_name)
            raw_name = winreg.QueryValueEx(asubkey, "DisplayName")[0]
            name = clean_string(raw_name)

            try:
                version = winreg.QueryValueEx(asubkey, "DisplayVersion")[0]
            except EnvironmentError:
                version = 'undefined'
            try:
                raw_publisher = winreg.QueryValueEx(asubkey, "Publisher")[0]
                publisher = clean_string(raw_publisher)
            except EnvironmentError:
                publisher = 'undefined'
            
            software_list.append({
                "name": name,
                "version": version,
                "publisher": publisher
            })
        except EnvironmentError:
            continue

    return software_list

# Load vendor and product data
vendor_csv_path = base_dir / 'Combined_Vendors.csv'  # Update with actual path
product_csv_path = base_dir / 'Combined_Products.csv'  # Update with actual path
vendors, products = load_csv_data(vendor_csv_path, product_csv_path)

# Get installed software from the registry
software_list = foo(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY) + foo(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY) + foo(winreg.HKEY_CURRENT_USER, 0)

# Get installed Microsoft Store apps
store_apps_list = list_store_apps()

# Combine both lists and remove duplicates (case-insensitive comparison)
unique_software = []
seen_names = set()
total_software = len(software_list) + len(store_apps_list)

for software in tqdm(software_list + store_apps_list, desc="Processing software", unit="app"):
    name_lower = software['name'].lower()
    if name_lower not in seen_names:
        seen_names.add(name_lower)
        standardized_name = standardize_name(software['name'], products)
        standardized_publisher = standardize_name(software['publisher'], vendors)
        unique_software.append({
            "DisplayName": standardized_name,
            "DisplayVersion": software['version'],
            "Publisher": standardized_publisher
        })

# Save to output.txt
with open("output.txt", "w") as file:
    for software in unique_software:
        file.write(f"DisplayName: {software['DisplayName']}\n")
        file.write(f"DisplayVersion: {software['DisplayVersion']}\n")
        file.write(f"Publisher: {software['Publisher']}\n")
        file.write('-' * 40 + '\n')

    file.write(f"\nNumber of unique installed apps: {len(unique_software)}")

print("")
def extract_version_numbers(text):
    # Pattern for version numbers (not dates)
    version_pattern = r'(?<![\d/])\d+(?:\.\d+){1,3}(?!\d|/\d)'
    versions = re.findall(version_pattern, text)
    
    # Remove duplicates while preserving order
    seen = set()
    return [v for v in versions if not (v in seen or seen.add(v))]

def clean_display_version(version_text):
    """Extract the actual version number from display version text that might include dates"""
    version_numbers = extract_version_numbers(version_text)
    return version_numbers[0] if version_numbers else version_text

def clean_word(word):
    # Remove version numbers before cleaning
    cleaned = re.sub(r'\d+(?:\.\d+){1,3}', '', word)
    return re.sub(r'\s+', '', cleaned).lower()

# Function to calculate the match score between a word and text
def calculate_match_score(word, text):
    word_cleaned = clean_word(word)
    text_cleaned = clean_word(text)
    if word_cleaned == text_cleaned:
        return len(word_cleaned)
    if word_cleaned in text_cleaned:
        return len(word_cleaned)
    return 0

# Modified function to extract app details with version handling
def extract_app_details(text_file):
    apps = []
    with open(text_file, 'r') as f:
        text = f.read()
        app_blocks = text.split('------------------------------')
        for block in app_blocks:
            display_name = re.search(r'DisplayName:\s*(.*)', block)
            display_version = re.search(r'DisplayVersion:\s*(.*)', block)
            publisher = re.search(r'Publisher:\s*(.*)', block)
            
            if display_name and display_version and publisher:
                name = display_name.group(1).strip()
                version = display_version.group(1).strip()
                
                # Extract version numbers from display name
                name_versions = extract_version_numbers(name)
                
                apps.append({
                    'DisplayName': name,
                    'DisplayVersion': version,
                    'Publisher': publisher.group(1).strip(),
                    'NameVersions': name_versions
                })
    return apps

# Function to find and match words from a CSV file against a given text value
def match_words_from_csv(csv_file, text_value):
    matches = []
    text_cleaned = clean_word(text_value)
    with open(csv_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile)
        unique_matches = set()
        for row in csv_reader:
            word = row[0]
            score = calculate_match_score(word, text_value)
            if score > 1:
                match = (word, score)
                if match not in unique_matches:
                    unique_matches.add(match)
                    matches.append(match)
    matches = sorted(matches, key=lambda x: x[1], reverse=True)
    return matches if matches else None

# Function to search for the vendor of a product using the CVE Details website
def search_vendor_from_product(product_name):
    base_url = "https://www.cvedetails.com/product-search.php"
    params = {
        'vendor_id': '0',
        'search': product_name
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Referer': "https://www.cvedetails.com/product-list.php"
    }
    response = requests.get(base_url, headers=headers, params=params)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        vendor_tag = soup.find('a', href=re.compile(r'/vendor/\d+/'))
        if vendor_tag:
            return vendor_tag.text.strip()
    return None

# Function to save lower-ranked product matches for later verification
def save_lower_rank_products(filename, product, rank, serial_number):
    with open(filename, 'a') as f:
        f.write(f"{serial_number},{product},{rank}\n")

# Function to load known vendor names from an external file
def load_known_vendors(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        return []  # Return an empty list if the file is not found

# Modified main function with version handling
# ... (all previous code remains the same until the process_apps function)

def process_apps(product_csv, vendor_csv, text_file, output_file, lower_rank_file, known_vendors_file):
    apps = extract_app_details(text_file)
    serial_number = 1
    known_vendors = load_known_vendors(known_vendors_file)

    with open(output_file, 'w') as f:
        # Initialize tqdm progress bar
        for app in tqdm(apps, desc="Processing applications", unit="app", ncols=80):
            display_name = app['DisplayName']
            publisher = app['Publisher']
            raw_display_version = app['DisplayVersion']
            
            # Clean the display version first (remove dates, keep only version number)
            display_version = clean_display_version(raw_display_version)
            
            # Handle version numbers in name
            name_versions = extract_version_numbers(display_name)
            final_name = display_name
            final_version = display_version
            additional_version = None

            # If version numbers found in name
            if name_versions:
                for name_version in name_versions:
                    if name_version == display_version:
                        final_name = re.sub(r'\s*' + re.escape(name_version) + r'\s*', ' ', display_name).strip()
                        break
                    else:
                        final_name = re.sub(r'\s*' + re.escape(name_version) + r'\s*', ' ', display_name).strip()
                        additional_version = name_version
            
            # Product matching
            product_matches = match_words_from_csv(product_csv, final_name)
            product_name = product_matches[0][0] if product_matches else final_name

            # Vendor handling
            if any(known_vendor in publisher for known_vendor in known_vendors):
                vendor_name = publisher
                website_vendor = search_vendor_from_product(product_name)
                if website_vendor and not any(known_vendor in website_vendor for known_vendor in known_vendors):
                    for rank, (lower_rank_product, score) in enumerate(product_matches[1:], start=2):
                        save_lower_rank_products(lower_rank_file, lower_rank_product, rank, serial_number)
                        lower_rank_vendor = search_vendor_from_product(lower_rank_product)
                        if any(known_vendor in lower_rank_vendor for known_vendor in known_vendors):
                            product_name = lower_rank_product
                            break
                    else:
                        serial_number += 1
                        continue
            else:
                vendor_matches = match_words_from_csv(vendor_csv, publisher)
                vendor_name = vendor_matches[0][0] if vendor_matches else search_vendor_from_product(product_name)
                for known_vendor in known_vendors:
                    if vendor_name and known_vendor in vendor_name:
                        vendor_name = known_vendor
                        break

            # Write output
            f.write('------------------------------\n')
            f.write(f'DisplayName: {product_name}\n')
            f.write(f'DisplayVersion: {final_version}\n')
            if additional_version:
                f.write(f'AdditionalVersion: {additional_version}\n')
            f.write(f'Publisher: {vendor_name}\n')
            serial_number += 1

# Example usage (unchanged)
product_csv = 'Combined_Products.csv'
vendor_csv = 'Combined_Vendors.csv'
text_file = 'output.txt'
output_file = 'processed_output.txt'
lower_rank_file = 'lower_rank_products.csv'
known_vendors_file = 'known_vendors.csv'

process_apps(product_csv, vendor_csv, text_file, output_file, lower_rank_file, known_vendors_file)

class VulnerabilityReport:
    def __init__(self):
        self.vulns_by_app = {}
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        ))
        self.styles.add(ParagraphStyle(
            name='AppName',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10
        ))
        self.styles.add(ParagraphStyle(
            name='SeverityHigh',
            parent=self.styles['Normal'],
            textColor=colors.red
        ))
        self.styles.add(ParagraphStyle(
            name='SeverityMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange
        ))
        self.styles.add(ParagraphStyle(
            name='SeverityLow',
            parent=self.styles['Normal'],
            textColor=colors.green
        ))

    def add_vulnerability(self, app_name, version, vendor, vuln_data):
        key = f"{app_name} ({vendor})"
        if key not in self.vulns_by_app:
            self.vulns_by_app[key] = {
                'version': version,
                'vulnerabilities': []
            }
        self.vulns_by_app[key]['vulnerabilities'].append(vuln_data)

    def get_severity_style(self, cvss_score):
        if cvss_score >= 7.0:
            return self.styles['SeverityHigh']
        elif cvss_score >= 4.0:
            return self.styles['SeverityMedium']
        else:
            return self.styles['SeverityLow']

    def generate_pdf(self, output_file):
        doc = SimpleDocTemplate(
            output_file,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        content = []

        # Title
        title = Paragraph(
            "Vulnerability Assessment Report",
            self.styles['CustomTitle']
        )
        content.append(title)

        # Date
        date_text = Paragraph(
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Normal']
        )
        content.append(date_text)
        content.append(Spacer(1, 30))

        # Executive Summary
        content.append(Paragraph("Executive Summary", self.styles['Heading2']))
        total_apps = len(self.vulns_by_app)
        total_vulns = sum(len(app_data['vulnerabilities']) for app_data in self.vulns_by_app.values())
        high_vulns = sum(1 for app_data in self.vulns_by_app.values() 
                        for vuln in app_data['vulnerabilities'] 
                        if vuln['cvss_score'] >= 7.0)
        
        summary_data = [
            ["Total Applications Scanned:", str(total_apps)],
            ["Total Vulnerabilities Found:", str(total_vulns)],
            ["High Severity Vulnerabilities (CVSS ≥ 7.0):", str(high_vulns)]
        ]
        
        summary_table = Table(summary_data, colWidths=[4*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        content.append(summary_table)
        content.append(Spacer(1, 20))

        # Detailed Findings
        content.append(Paragraph("Detailed Findings", self.styles['Heading2']))
        content.append(Spacer(1, 10))

        if self.vulns_by_app:
            # Sort applications by highest CVSS score
            sorted_apps = sorted(
                self.vulns_by_app.items(),
                key=lambda x: max(v['cvss_score'] for v in x[1]['vulnerabilities']),
                reverse=True
            )

            for app_name, app_data in sorted_apps:
                content.append(Paragraph(
                    f"{app_name} (Version: {app_data['version']})",
                    self.styles['AppName']
                ))

                # Sort vulnerabilities by CVSS score
                sorted_vulns = sorted(
                    app_data['vulnerabilities'],
                    key=lambda x: x['cvss_score'],
                    reverse=True
                )

                for vuln in sorted_vulns:
                    severity_style = self.get_severity_style(vuln['cvss_score'])
                    
                    vuln_header = Paragraph(
                        f"<b>{vuln['cve_id']}</b> (CVSS: {vuln['cvss_score']})",
                        severity_style
                    )
                    content.append(vuln_header)
                    
                    content.append(Paragraph(
                        f"<b>Published:</b> {vuln['publish_date']}",
                        self.styles['Normal']
                    ))
                    
                    content.append(Paragraph(
                        f"<b>Summary:</b> {vuln['summary']}",
                        self.styles['Normal']
                    ))
                    
                    content.append(Spacer(1, 10))

                content.append(Spacer(1, 20))
        else:
            content.append(Paragraph(
                "No vulnerabilities were found in the scanned applications.",
                self.styles['Normal']
            ))

        doc.build(content)

def search_cve(vendor, product, version, report):
    base_url = "https://www.cvedetails.com/version-search.php"
    params = {
        'vendor': vendor,
        'product': product,
        'version': version
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': base_url,
        'Upgrade-Insecure-Requests': '1'
    }

    response = requests.get(base_url, headers=headers, params=params)
    if response.status_code == 200:
        if response.history:
            final_url = response.url
            print(f"Searching version {version} - Redirected to: {final_url}")

            final_response = requests.get(final_url, headers=headers)
            if final_response.status_code == 200:
                final_soup = BeautifulSoup(final_response.content, 'html.parser')
                results = final_soup.find_all('div', class_='border-top py-3 px-2 hover-bg-light')

                if results:
                    print(f"Found vulnerabilities for {vendor} {product} {version}")
                    for result in results:
                        cve_id_tag = result.find('h3', attrs={'data-tsvfield': 'cveId'})
                        cve_id = cve_id_tag.text.strip() if cve_id_tag else "N/A"

                        summary_tag = result.find('div', attrs={'data-tsvfield': 'summary'})
                        summary = summary_tag.text.strip() if summary_tag else "N/A"

                        publish_date_tag = result.find('div', attrs={'data-tsvfield': 'publishDate'})
                        publish_date = publish_date_tag.text.strip() if publish_date_tag else "N/A"

                        cvss_score_tag = result.find('div', attrs={'data-tsvfield': 'maxCvssBaseScore'})
                        cvss_score = cvss_score_tag.text.strip() if cvss_score_tag else "N/A"
                        
                        vuln_data = {
                            'cve_id': cve_id,
                            'summary': summary,
                            'publish_date': publish_date,
                            'cvss_score': float(cvss_score) if cvss_score != "N/A" else 0
                        }
                        
                        # Add vulnerability to report
                        report.add_vulnerability(product, version, vendor, vuln_data)
                    return True
                else:
                    print(f"No vulnerabilities found for version {version}")
                    return False
    return False
processed_output_path = base_dir / 'processed_output.txt'

def fetch_cve_for_applications(file_path):
    report = VulnerabilityReport()
    
    # Load application details from the file
    with open(file_path, 'r') as file:
        lines = file.readlines()

    vendor = product = version = additional_version = None
    app_count = lines.count("------------------------------")  # Total applications in the file

    # Prevent division by zero in case app_count is 0
    if app_count == 0:
        print("No applications found to process.")
        return  # Exit the function if no applications are found

    # Initialize progress bar for processing applications
    with tqdm(total=app_count, desc="Processing Applications", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} {percentage:.0f}%") as progress_bar:
        search_progress_bar = tqdm(total=app_count, desc="Searching for applications", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} {percentage:.0f}%", leave=False)
        
        for line in lines:
            line = line.strip()

            if line.startswith("DisplayName:"):
                product = line.split(":")[1].strip()
            elif line.startswith("DisplayVersion:"):
                version = line.split(":")[1].strip()
            elif line.startswith("AdditionalVersion:"):
                additional_version = line.split(":")[1].strip()
            elif line.startswith("Publisher:"):
                vendor = line.split(":")[1].strip()
            elif line == "------------------------------":
                # Check if we have enough information to search for vulnerabilities
                if vendor and product:
                    # Searching without a new progress bar
                    if version:
                        search_cve(vendor, product, version, report)
                    elif additional_version:
                        search_cve(vendor, product, additional_version, report)

                    # Update the search progress bar
                    search_progress_bar.update(1)

                # Reset fields for the next application
                vendor = product = version = additional_version = None
                
                # Update the processing progress bar
                progress_bar.update(1)  

        search_progress_bar.close()  # Close the search progress bar after all searches are complete

    # Generate the report after all searches are complete
    report.generate_pdf(str(processed_output_path))
    tqdm.write("\nReport has been generated as 'vulnerability_report.pdf'")

# Call the function with your text file
fetch_cve_for_applications(str(processed_output_path))