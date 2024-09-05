import re
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from flask import Flask, render_template, request
import threading
import webbrowser

app = Flask(__name__)

# Set up Selenium options for headless mode
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--headless")  # Enable headless mode

def validate_cve_id(cve_id):
    """Validate the format of the CVE ID."""
    pattern = r"CVE-\d{4}-\d{4,7}"
    return re.match(pattern, cve_id) is not None

def check_cve_status(cve_id):
    """Check if the CVE ID is published, reserved, or rejected."""
    url = f"https://cveawg.mitre.org/api/cve-id/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get('state')
    return None

def get_affected_assets(cve_id):
    """Get affected vendor and product information using the CVE API."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    affected_assets = []
    
    if response.status_code == 200:
        data = response.json()
        try:
            for affected in data['containers']['cna']['affected']:
                vendor = affected['vendor']
                product = affected['product']
                affected_assets.append({"vendor": vendor, "product": product})
        except KeyError:
            print(f"Error parsing affected assets for CVE {cve_id}.")
    return affected_assets

def collect_data(cve_id, report):
    """Use Selenium to collect data from various sources."""
    service = Service(executable_path='chromedriver.exe')  # Update the path to your chromedriver
    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        # Scrape NIST NVD for important information
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        driver.get(nvd_url)

        try:
            # Use WebDriverWait to wait for elements to load
            cvss_panel_element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.XPATH, "//*[@id='Vuln3CvssPanel']"))
            )
            
            # Locate CVSS score and vector using relative XPath
            cvss_score_element = cvss_panel_element.find_element(By.XPATH, ".//span[@class='severityDetail']")
            cvss_vector_element = cvss_panel_element.find_element(By.XPATH, ".//a[@id='Cvss3NistCalculatorAnchor']")
            
            # Extract and store CVSS score and vector
            report["cvss_score"] = cvss_score_element.text.strip()
            vector_full = cvss_vector_element.get_attribute("href").split('vector=')[1]
            report["cvss_details"] = vector_full.split('&')[0]
        
        except Exception as e:
            print(f"Error finding CVSS score and vector: {e}")

        try:
            # Wait for the description element to be visible using XPath
            description_element = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.XPATH, "//p[@data-testid='vuln-description']"))
            )
            report["description"] = description_element.text.strip()
        except Exception as e:
            print(f"Error finding description: {e}")

        # Use the API to get affected assets
        report["affected_assets"] = get_affected_assets(cve_id)

        # Extract valid reference links
        report["references"] = get_valid_references(driver)
        # Open the top 3 reference links in the default web browser
        for link in report["references"][:3]:
            webbrowser.open_new_tab(link)
        driver.switch_to.window(driver.window_handles[0])  # Switch back to the original tab
        # Scrape Exploit DB for exploits
        exploitdb_url = f"https://www.exploit-db.com/search?cve={cve_id}"
        driver.get(exploitdb_url)
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.XPATH, "//*[@id='exploits-table']/tbody/tr/td[5]"))
            )
            exploit_rows = driver.find_elements(By.XPATH, "//*[@id='exploits-table']/tbody/tr")
            for row in exploit_rows:
                title_element = row.find_element(By.XPATH, "./td[5]")
                title_text = title_element.text.strip()
                title_link_element = title_element.find_element(By.TAG_NAME, "a")
                title_link = title_link_element.get_attribute("href")
                download_link = title_link.replace("/exploits/", "/download/")  # Adjusted link replacement
                report["exploits"].append({"title": title_text, "title_link": title_link, "download_link": download_link})
        except Exception as e:
            print(f"No exploits found on Exploit DB for {cve_id}: {e}")

    finally:
        driver.quit()

def get_valid_references(driver):
    """Extracts up to 5 valid reference links from the NIST reference table."""
    valid_links = []
    try:
        reference_links = driver.find_elements(By.XPATH, "//table[contains(@data-testid, 'vuln-hyperlinks-table')]//a")
        for link in reference_links:
            if len(valid_links) >= 5:
                break
            href = link.get_attribute("href")
            if check_link_exists(href):
                valid_links.append(href)
    except Exception as e:
        print(f"Error finding references: {e}")
    return valid_links

def check_link_exists(url):
    """Checks if a URL exists by making an HTTP HEAD request."""
    try:
        response = requests.head(url, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException:
        return False

def start_data_collection(cve_id):
    """Initiate data collection in a separate thread."""
    report = {
        "cve_id": cve_id,
        "cvss_score": "",
        "cvss_details": "",
        "description": "",
        "affected_assets": [],
        "exploits": [],
        "references": []
    }
    thread = threading.Thread(target=collect_data, args=(cve_id, report))
    thread.start()
    thread.join()  # Wait for the thread to finish
    return report

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form['cve_id']
        if not validate_cve_id(cve_id):
            return render_template('index.html', error="Invalid CVE ID format. Please enter a valid CVE ID.")
        
        status = check_cve_status(cve_id)
        if status:
            if status in ['RESERVED', 'REJECTED']:
                return render_template('index.html', error=f"The CVE ID {cve_id} is {status}. Cannot proceed with data collection.")
            elif status != 'PUBLISHED':
                warning = "The CVE ID is not in a published state. Proceed with caution."
                report = start_data_collection(cve_id)
                return render_template('report.html', report=report, warning=warning, status=status)
            
            report = start_data_collection(cve_id)
            return render_template('report.html', report=report, status=status)
        else:
            return render_template('index.html', error=f"Could not determine the status of the CVE ID {cve_id}.")
    
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
