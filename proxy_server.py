import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests

# --- IMPORTANT CONFIGURATION ---
# Note: You must set your actual VirusTotal API key as an environment variable (VT_API_KEY)
# on the machine running this proxy server.
VT_API_KEY = os.environ.get("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")

# VirusTotal API endpoint for file hash lookups
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
VT_HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept": "application/json"
}
# --- END CONFIGURATION ---

app = Flask(__name__)
# Enable CORS for all routes, allowing the HTML page on another device to connect
CORS(app)

# ----------------------------------------------------
# 1. NEW ROUTE TO SERVE THE HTML FILE
# This allows external devices to load the web page content from the server's IP.
# ----------------------------------------------------
@app.route('/')
def serve_html():
    """Serves the main HTML application file."""
    # Assumes malware_checker_web.html is in the same directory as the Python script.
    return send_from_directory('.', 'malware_checker_web.html')


# ----------------------------------------------------
# 2. API ROUTE (Original Functionality)
# ----------------------------------------------------
@app.route('/api/check-hash', methods=['POST'])
def check_hash():
    """
    Receives a file hash from the web client and proxies the request
    to the VirusTotal API.
    """
    # 1. Basic validation and extraction
    try:
        data = request.get_json()
        file_hash = data.get('hash')
    except Exception:
        # Catches issues like non-JSON or missing data
        return jsonify({"error": "Invalid request format or missing hash."}), 400

    if not file_hash:
        return jsonify({"error": "Hash is required."}), 400

    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("ERROR: VirusTotal API Key is missing or default.")
        return jsonify({"error": "VirusTotal API Key not configured on the server."}), 500

    # 2. VirusTotal API Lookup
    try:
        # Construct the specific URL for the hash lookup
        url = f"{VT_API_URL}{file_hash}"
        
        print(f"Proxying request for hash: {file_hash}")
        vt_response = requests.get(url, headers=VT_HEADERS, timeout=15)
        
        # Check for successful API response (HTTP 200)
        if vt_response.status_code == 200:
            vt_data = vt_response.json()
            
            # Extract relevant stats
            attributes = vt_data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            # Format the required output for the frontend
            result = {
                "status": 200,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "clean": stats.get('harmless', 0) + stats.get('undetected', 0),
                "total": stats.get('malicious', 0) + stats.get('suspicious', 0) + stats.get('harmless', 0) + stats.get('undetected', 0)
            }
            return jsonify(result), 200
        
        # Handle "Not Found" status from VirusTotal (usually 404 or 400/401 for other errors)
        elif vt_response.status_code == 404:
            # File hash is not known to VirusTotal
            return jsonify({"status": 404, "message": "Hash unknown to VirusTotal."}), 200
        else:
            # Handle other API errors (e.g., rate limits, invalid API key, etc.)
            error_message = vt_response.json().get('error', {}).get('message', 'Unknown VirusTotal API Error.')
            print(f"VirusTotal API Error: {vt_response.status_code} - {error_message}")
            return jsonify({"error": f"VirusTotal API failed: {error_message}"}), 502

    except requests.exceptions.Timeout:
        return jsonify({"error": "VirusTotal API request timed out."}), 504
    except requests.exceptions.RequestException as e:
        print(f"Network error during VT request: {e}")
        return jsonify({"error": f"Network error connecting to VirusTotal: {e}"}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": f"An unexpected server error occurred: {e}"}), 500


if __name__ == '__main__':
    # Run server accessible to the local network (IMPORTANT for mobile access)
    # The host must be 0.0.0.0 for external devices to connect
    print("----------------------------------------------------------------------")
    print(f"Server is starting. Use YOUR computer's IPv4 address, NOT 127.0.0.1.")
    print("----------------------------------------------------------------------")
    app.run(host='0.0.0.0', port=5800, debug=True)

