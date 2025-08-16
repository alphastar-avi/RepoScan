from flask import Flask, request, jsonify, render_template
import subprocess
import json
import os
import shutil

app = Flask(__name__)

# Helper function to run sast_scan.py and format its output
def run_sast_scan_and_format(repo_url, language=None):
    # Construct the command to run sast_scan.py
    command = ["sast_env/bin/python3", "sast_scan.py", repo_url]
    if language:
        command.append(language)

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        semgrep_output = json.loads(process.stdout)

        formatted_output = ""
        if not semgrep_output.get("results"):
            formatted_output = "No vulnerabilities found."
        else:
            for result in semgrep_output["results"]:
                formatted_output += f"---Path: {result['path']}:{result['start']['line']}\n"
                formatted_output += f"Rule ID: {result['check_id']}\n"
                formatted_output += f"Severity: {result['extra']['severity']}\n"
                formatted_output += f"Message: {result['extra']['message']}\n"
                formatted_output += f"Vulnerable Code:{result['extra']['lines']}\n"
                formatted_output += "---\n"
        return formatted_output
    except subprocess.CalledProcessError as e:
        return f"Error running SAST scan: {e.stderr}"
    except json.JSONDecodeError:
        return f"Error parsing SAST scan output: {process.stdout}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    repo_url = data.get('repo_url')
    pat_token = data.get('pat_token') # Not directly used by sast_scan.py, but can be embedded in URL
    language = data.get('language')

    if not repo_url:
        return jsonify({"error": "Repository URL is required"}), 400

    # Embed PAT into the URL if provided
    if pat_token:
        # Assuming the URL is always github.com for simplicity
        # A more robust solution would parse the URL properly
        if "github.com" in repo_url and "@" not in repo_url:
            parts = repo_url.split("github.com/")
            repo_url = f"{parts[0]}github.com/{pat_token}@{parts[1]}"
        else:
            return jsonify({"error": "PAT token can only be embedded in github.com URLs without existing credentials"}), 400

    formatted_results = run_sast_scan_and_format(repo_url, language)
    return jsonify({"results": formatted_results})

if __name__ == '__main__':
    app.run(debug=True, port=8080)