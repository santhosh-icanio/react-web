import os
import time
import requests
from flask import Flask, request, render_template_string, send_file

# ------------------------
# Config
# ------------------------
API_KEY = "cdbb96a7303aec52202aec657f9447564a034289a4074c8102b701547b351f91"
UPLOAD_FOLDER = "uploads"
SPLIT_FOLDER = "split_parts"
MAX_PART_SIZE_MB = 100
ALLOWED_EXTENSIONS = {'zip'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SPLIT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ------------------------
# HTML Template
# ------------------------
UPLOAD_FORM = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VirusTotal Scan Results</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(to right, #e0f7fa, #ffffff);
      margin: 0;
      padding: 0;
      color: #333;
    }
    .container {
      max-width: 900px;
      margin: 50px auto;
      padding: 40px;
      background: #fff;
      box-shadow: 0 8px 16px rgba(0,0,0,0.1);
      border-radius: 12px;
    }
    h2, h3 {
      text-align: center;
      color: #007BFF;
    }
    .result {
      background: #f1faff;
      border-left: 6px solid #007BFF;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 8px;
    }
    .result h4 {
      color: #007BFF;
      margin: 0 0 10px;
    }
    .result ul {
      list-style: none;
      padding: 0;
    }
    .result ul li {
      padding: 4px 0;
      font-size: 14px;
    }
    .download-btn {
      display: block;
      text-align: center;
      margin-top: 20px;
      padding: 10px 20px;
      background-color: #007BFF;
      color: white;
      font-weight: bold;
      border-radius: 5px;
      font-size: 16px;
      width: 220px;
      margin-left: auto;
      margin-right: auto;
      text-decoration: none;
    }
    .download-btn:hover {
      background-color: #0056b3;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>VirusTotal Scan Report</h2>
    <h3>Scan Results</h3>
    {% for result in results %}
      <div class="result">
        <p><strong>Stats:</strong> {{ result.stats }}</p>
        <h4>{{ result.filename }}</h4>
        <ul>
          {% for engine, info in result.engines.items() %}
            <li><strong>{{ engine }}</strong>: {{ info.category }} ({{ info.method }})</li>
          {% endfor %}
        </ul>
      </div>
    {% endfor %}
  </div>
</body>
</html>
"""



# ------------------------
# Helper Functions
# ------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def split_zip_file(input_path, output_dir):
    max_part_size = MAX_PART_SIZE_MB * 1024 * 1024
    file_size = os.path.getsize(input_path)
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    extension = os.path.splitext(input_path)[1]
    created_files = []

    if file_size <= max_part_size:
        return [input_path]

    with open(input_path, 'rb') as f:
        part_num = 1
        bytes_written = 0
        part_file = None

        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            if bytes_written == 0:
                part_filename = f"{base_name}.part{part_num:03d}{extension}"
                part_path = os.path.join(output_dir, part_filename)
                part_file = open(part_path, 'wb')
                created_files.append(part_path)
            part_file.write(chunk)
            bytes_written += len(chunk)
            if bytes_written >= max_part_size:
                part_file.close()
                part_num += 1
                bytes_written = 0
        if part_file:
            part_file.close()

    return created_files

def upload_to_virustotal(file_path):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
    data = response.json()
    if "data" not in data:
        raise ValueError(f"Error fetching upload URL: {data}")

    upload_url = data["data"]

    with open(file_path, "rb") as f:
        files = {"file": f}
        upload_response = requests.post(upload_url, files=files, headers={"x-apikey": API_KEY})
        upload_data = upload_response.json()
        return upload_data.get("data", {}).get("id")

def poll_for_result(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    while True:
        response = requests.get(url, headers=headers)
        data = response.json()
        if data["data"]["attributes"]["status"] == "completed":
            break
        time.sleep(5)

    return {
        "engines": data["data"]["attributes"]["results"],
        "stats": data["data"]["attributes"]["stats"]
    }

# ------------------------
# Routes
# ------------------------
@app.route('/', methods=['GET', 'POST'])
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    results = []

    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = os.path.basename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)

            print("File uploaded. Scanning...")  # Log for debug

            parts = split_zip_file(filepath, SPLIT_FOLDER)
            for part in parts:
                analysis_id = upload_to_virustotal(part)
                result = poll_for_result(analysis_id)
                results.append({
                    "filename": os.path.basename(part),
                    "engines": result["engines"],
                    "stats": result["stats"]
                })

            # Generate HTML report
            html_report = render_template_string(UPLOAD_FORM, results=results)
            os.makedirs("static", exist_ok=True)
            report_path = "static/scan_results.html"
            with open(report_path, "w") as f:
                f.write(html_report)

            # Return report file directly for download
            return send_file(report_path, as_attachment=True)

        else:
            return "Only .zip files are allowed", 400

    return render_template_string(UPLOAD_FORM, results=results)


@app.route('/report')
def view_report():
    report_path = os.path.join("static", "scan_results.html")
    if os.path.exists(report_path):
        return send_file(report_path)
    return "Report not found", 404

@app.route('/download_report')
def download_report():
    report_path = os.path.join("static", "scan_results.html")
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    return "Report not found", 404

# ------------------------
# Run App
# ------------------------
if __name__ == '__main__':
    app.run(debug=True, port=5000)
