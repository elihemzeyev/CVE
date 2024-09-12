
# CVE Report Generator

## Project Description
The **CVE Report Generator** is a web application designed to fetch and generate detailed reports for Common Vulnerabilities and Exposures (CVE) IDs. It utilizes Selenium for web scraping and provides downloadable reports in various formats such as PDF, DOCX, and HTML. The application ensures that CVE IDs are valid, checks their current status, and gathers detailed information from multiple sources like NIST NVD, Exploit DB, and MITRE.

## Features
- **CVE ID Validation:** Validates the format and existence of a given CVE ID.
- **CVE Status Check:** Determines if a CVE ID is published, reserved, or rejected.
- **Data Collection:** Retrieves CVSS scores, vectors, descriptions, affected assets, and available exploits.
- **Downloadable Reports:** Generates reports in PDF, DOCX, and HTML formats.
- **Reference Links:** Extracts and verifies reference links from NIST and Exploit DB.

## Dependencies
- Python 3.x
- Flask
- Selenium
- Requests
- FPDF
- python-docx
- WebDriver (e.g., ChromeDriver)

## Instructions for Running the Project

1. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

2. Run the Flask application:
    Go to "CVE project" folder:
    ```bash
    python app.py
    ```

3. Open your web browser and navigate to:
    ```
    http://localhost:5000
    ```

5. Enter a valid CVE ID in the input field and submit. You can then choose the report format (PDF, DOCX, HTML) and download it.

## Endpoints
- **Home:** `/` (GET, POST) - Submits a CVE ID and displays the report.
- **Download:** `/download/<filetype>/<cve_id>` (GET) - Downloads the report in the specified file type (pdf, docx, or html).
