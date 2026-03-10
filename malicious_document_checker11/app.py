from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import requests, os, time
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
VT_API_KEY = os.getenv("VT_API_KEY")

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def css():
    return send_from_directory('.', 'style.css')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)
    try:
        files = {"file": (filename, file)}
        headers = {"x-apikey": VT_API_KEY}
        upload_resp = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)

        if upload_resp.status_code != 200:
            return jsonify({"error": upload_resp.text}), upload_resp.status_code

        data_id = upload_resp.json()["data"]["id"]
        for _ in range(60):
            analysis_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{data_id}", headers=headers)
            result_data = analysis_resp.json()
            if result_data["data"]["attributes"]["status"] == "completed":
                stats = result_data["data"]["attributes"]["stats"]
                malicious = stats["malicious"] > 0
                link = f"https://www.virustotal.com/gui/file/{data_id}/detection"
                return jsonify({"malicious": malicious, "link": link})
            time.sleep(1)

        return jsonify({"error": "Timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
