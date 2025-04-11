import requests
import os
import time
import zipfile
import io
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration
API_KEY = "cdbb96a7303aec52202aec657f9447564a034289a4074c8102b701547b351f91"
FILE_PATH = "node_modules"
REPORT_FILE = "index.html"
MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB max zip file size
MAX_WAIT_TIME = 3600  # Maximum wait time for scan completion (1 hour)
SCAN_TIMEOUT = 30  # Timeout for API requests in seconds

def setup_session():
    """Configure requests session with retries and SSL verification"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[408, 429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def get_upload_url(session):
    """Get the upload URL from VirusTotal"""
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {"x-apikey": API_KEY}
    try:
        response = session.get(url, headers=headers, timeout=SCAN_TIMEOUT)
        response.raise_for_status()
        return response.json().get('data')
    except requests.exceptions.RequestException as e:
        print(f"Error getting upload URL: {str(e)}")
        return None

def create_zip_chunks(directory_path):
    """Create zip files of max MAX_ZIP_SIZE from directory contents"""
    zip_chunks = []
    current_zip_buffer = io.BytesIO()
    current_zip = zipfile.ZipFile(current_zip_buffer, 'w', zipfile.ZIP_DEFLATED)
    current_zip_size = 0
    zip_index = 1
    
    # Get current timestamp for filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_size = os.path.getsize(file_path)
                
                # Skip files larger than MAX_ZIP_SIZE
                if file_size > MAX_ZIP_SIZE:
                    print(f"Skipping large file: {file} ({file_size/1024/1024:.2f}MB)")
                    continue
                    
                # If current zip would exceed size limit with this file, finalize it
                if current_zip_size + file_size > MAX_ZIP_SIZE:
                    current_zip.close()
                    zip_data = current_zip_buffer.getvalue()
                    if len(zip_data) > 0:
                        zip_name = f"scan_chunk_{timestamp}_{zip_index}.zip"
                        with open(zip_name, 'wb') as f:
                            f.write(zip_data)
                        zip_chunks.append(zip_name)
                        zip_index += 1
                    
                    # Start new zip
                    current_zip_buffer = io.BytesIO()
                    current_zip = zipfile.ZipFile(current_zip_buffer, 'w', zipfile.ZIP_DEFLATED)
                    current_zip_size = 0
                
                # Add file to zip
                arcname = os.path.relpath(file_path, start=directory_path)
                current_zip.write(file_path, arcname)
                current_zip_size += file_size
                
            except Exception as e:
                print(f"Error processing {file}: {str(e)}")
    
    # Finalize the last zip
    current_zip.close()
    zip_data = current_zip_buffer.getvalue()
    if len(zip_data) > 0:
        zip_name = f"scan_chunk_{timestamp}_{zip_index}.zip"
        with open(zip_name, 'wb') as f:
            f.write(zip_data)
        zip_chunks.append(zip_name)
    
    return zip_chunks

def scan_zip_file(session, zip_path, upload_url):
    """Scan a zip file and return the report"""
    try:
        headers = {"x-apikey": API_KEY}
        with open(zip_path, "rb") as file:
            files = {"file": (os.path.basename(zip_path), file)}
            response = session.post(
                upload_url,
                headers=headers,
                files=files,
                timeout=SCAN_TIMEOUT
            )
            response.raise_for_status()
            scan_id = response.json()["data"]["id"]
            print(f"Scanning {os.path.basename(zip_path)}...")
            return get_scan_report(session, scan_id)
    except Exception as e:
        print(f"Error scanning {zip_path}: {str(e)}")
        return None

def get_scan_report(session, scan_id):
    """Poll the scan results until completed"""
    report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": API_KEY}
    start_time = time.time()
    
    while True:
        if time.time() - start_time > MAX_WAIT_TIME:
            raise Exception("Scan timed out after 1 hour")
        
        try:
            response = session.get(report_url, headers=headers, timeout=SCAN_TIMEOUT)
            response.raise_for_status()
            report = response.json()
            status = report['data']['attributes']['status']
            
            if status == 'completed':
                return report
            elif status in ['queued', 'in-progress']:
                time.sleep(30)
            else:
                raise Exception(f"Scan failed with status: {status}")
        except requests.exceptions.RequestException as e:
            print(f"Error getting report: {str(e)}")
            time.sleep(30)

def generate_html_report(zip_reports, scanned_path):
    """Generate comprehensive HTML report with full details"""
    # Calculate summary statistics
    total_chunks = len(zip_reports)
    malicious_chunks = sum(1 for r in zip_reports if r and r['data']['attributes']['stats']['malicious'] > 0)
    suspicious_chunks = sum(1 for r in zip_reports if r and r['data']['attributes']['stats']['suspicious'] > 0)
    
    # Prepare detailed engine results
    all_engine_results = []
    for report in zip_reports:
        if not report:
            continue
            
        attributes = report['data']['attributes']
        results = attributes.get('results', {})
        stats = attributes['stats']
        
        # Sort engines by detection status
        sorted_engines = sorted(
            results.items(),
            key=lambda x: (
                0 if x[1]['category'] == 'malicious' else 
                1 if x[1]['category'] == 'suspicious' else 
                2
            )
        )
        
        all_engine_results.append({
            'zip_name': report.get('zip_name', 'Unknown'),
            'stats': stats,
            'engines': sorted_engines,
            'scan_date': datetime.fromtimestamp(attributes['date']).strftime('%Y-%m-%d %H:%M:%S'),
            'analysis_url': f"https://www.virustotal.com/gui/file/{report['data']['id']}"
        })
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>VirusTotal Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background: #f4f4f4; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .chunk-summary {{ margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f4f4f4; font-weight: bold; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .malicious {{ color: #d32f2f; font-weight: bold; }}
        .suspicious {{ color: #ff9800; font-weight: bold; }}
        .clean {{ color: #388e3c; }}
        .risk-indicator {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
            margin-left: 10px;
        }}
        .high-risk {{ background-color: #ffebee; color: #d32f2f; }}
        .medium-risk {{ background-color: #fff8e1; color: #ff9800; }}
        .low-risk {{ background-color: #e8f5e9; color: #388e3c; }}
        .engine-table {{ margin-top: 10px; }}
        .toggle-details {{ 
            background: #4CAF50;
            color: white;
            border: none;
            padding: 5px 10px;
            cursor: pointer;
            border-radius: 3px;
            margin: 10px 0;
        }}
        .hidden {{ display: none; }}
        .engine-malicious {{ background-color: #ffebee; }}
        .engine-suspicious {{ background-color: #fff8e1; }}
    </style>
    <script>
        function toggleDetails(elementId) {{
            var element = document.getElementById(elementId);
            if (element.style.display === 'none') {{
                element.style.display = 'block';
            }} else {{
                element.style.display = 'none';
            }}
        }}
    </script>
</head>
<body>
    <h1>VirusTotal Scan Report</h1>
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Scanned Path:</strong> {scanned_path}</p>
        <p><strong>Total Zip Chunks Scanned:</strong> {total_chunks}</p>
        <p><strong>Chunks with Malicious Files:</strong> 
            <span class="{'malicious' if malicious_chunks > 0 else 'clean'}">
                {malicious_chunks}
                {f'<span class="risk-indicator high-risk">HIGH RISK</span>' if malicious_chunks > 0 else ''}
            </span>
        </p>
        <p><strong>Chunks with Suspicious Files:</strong> 
            <span class="{'suspicious' if suspicious_chunks > 0 else 'clean'}">
                {suspicious_chunks}
                {f'<span class="risk-indicator medium-risk">CAUTION</span>' if suspicious_chunks > 0 and malicious_chunks == 0 else ''}
            </span>
        </p>
        {f'<p class="risk-indicator low-risk">No malicious files detected in any chunks</p>' if malicious_chunks == 0 and suspicious_chunks == 0 else ''}
    </div>
    
    <h2>Detailed Scan Results</h2>"""
    
    # Add detailed results for each zip chunk
    for i, chunk in enumerate(all_engine_results, 1):
        html += f"""
    <div class="chunk-summary">
        <h3>Zip Chunk {i}: {chunk['zip_name']}</h3>
        <p>Scan Date: {chunk['scan_date']} | 
           <a href="{chunk['analysis_url']}" target="_blank">View on VirusTotal</a></p>
        
        <div class="summary">
            <p><strong>Malicious Detections:</strong> 
                <span class="{'malicious' if chunk['stats']['malicious'] > 0 else 'clean'}">
                    {chunk['stats']['malicious']}
                </span>
            </p>
            <p><strong>Suspicious Detections:</strong> 
                <span class="{'suspicious' if chunk['stats']['suspicious'] > 0 else 'clean'}">
                    {chunk['stats']['suspicious']}
                </span>
            </p>
            <p><strong>Undetected:</strong> {chunk['stats']['undetected']}</p>
            <p><strong>Harmless:</strong> {chunk['stats']['harmless']}</p>
        </div>
        
        <button class="toggle-details" onclick="toggleDetails('engine-details-{i}')">
            Toggle Engine Details
        </button>
        
        <div id="engine-details-{i}" class="hidden">
            <h4>Engine Results:</h4>
            <table class="engine-table">
                <tr>
                    <th>Engine</th>
                    <th>Result</th>
                    <th>Category</th>
                    <th>Method</th>
                    <th>Version</th>
                </tr>"""
        
        for engine, result in chunk['engines']:
            row_class = ''
            if result['category'] == 'malicious':
                row_class = 'engine-malicious'
            elif result['category'] == 'suspicious':
                row_class = 'engine-suspicious'
                
            html += f"""
                <tr class="{row_class}">
                    <td>{engine}</td>
                    <td>{result.get('result', 'N/A')}</td>
                    <td class="{'malicious' if result['category'] == 'malicious' else 'suspicious' if result['category'] == 'suspicious' else 'clean'}">
                        {result['category'].capitalize()}
                    </td>
                    <td>{result.get('method', 'N/A')}</td>
                    <td>{result.get('engine_version', 'N/A')}</td>
                </tr>"""
        
        html += """
            </table>
        </div>
    </div>"""
    
    html += f"""
    <footer style="margin-top: 30px; font-size: 0.8em; color: #666; border-top: 1px solid #eee; padding-top: 10px;">
        <p>Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>VirusTotal API v3 | Max zip size: {MAX_ZIP_SIZE/1024/1024:.0f}MB</p>
    </footer>
</body>
</html>"""
    
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"\nFull report generated: {os.path.abspath(REPORT_FILE)}")

def main():
    """Main execution function"""
    if not os.path.exists(FILE_PATH):
        print(f"Error: Path not found - {FILE_PATH}")
        return

    session = setup_session()
    try:
        if os.path.isdir(FILE_PATH):
            print(f"\nCreating zip chunks from directory: {FILE_PATH}")
            zip_chunks = create_zip_chunks(FILE_PATH)
            
            if not zip_chunks:
                print("No files were added to zip chunks")
                return
            
            print(f"\nCreated {len(zip_chunks)} zip chunk(s) for scanning")
            
            upload_url = get_upload_url(session)
            if not upload_url:
                print("Failed to get upload URL, aborting scan")
                return
            
            zip_reports = []
            for zip_path in zip_chunks:
                report = scan_zip_file(session, zip_path, upload_url)
                if report:
                    report['zip_name'] = os.path.basename(zip_path)
                    zip_reports.append(report)
                # Clean up the zip file
                try:
                    os.remove(zip_path)
                except:
                    pass
            
            if zip_reports:
                # Calculate summary statistics for console output
                malicious_chunks = sum(1 for r in zip_reports if r and r['data']['attributes']['stats']['malicious'] > 0)
                suspicious_chunks = sum(1 for r in zip_reports if r and r['data']['attributes']['stats']['suspicious'] > 0)
                
                # Print the summary to console
                print("\n=== Scan Summary ===")
                print(f"Scanned Path: {FILE_PATH}")
                print(f"Total Zip Chunks Scanned: {len(zip_reports)}")
                if malicious_chunks > 0:
                    print(f"Chunks with Malicious Files: {malicious_chunks} \033[91mHIGH RISK\033[0m")  # Red color for high risk
                else:
                    print(f"Chunks with Malicious Files: {malicious_chunks}")
                
                if suspicious_chunks > 0:
                    print(f"Chunks with Suspicious Files: {suspicious_chunks} \033[93mCAUTION\033[0m")  # Yellow color for caution
                else:
                    print(f"Chunks with Suspicious Files: {suspicious_chunks}")
                
                # Generate the HTML report
                generate_html_report(zip_reports, FILE_PATH)
            else:
                print("No zip chunks were successfully scanned")
                
        elif os.path.isfile(FILE_PATH):
            print("\nSingle file scanning not supported in this version. Please specify a directory.")
        else:
            print(f"Error: Path is neither file nor directory - {FILE_PATH}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")
    finally:
        session.close()
        print("\nScan completed")

if __name__ == "__main__":
    main()
