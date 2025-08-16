import sys
import subprocess
import json
import shutil
import os

def detect_project_type(clone_dir):
    if os.path.exists(os.path.join(clone_dir, "pom.xml")):
        return "java"
    if os.path.exists(os.path.join(clone_dir, "build.gradle")):
        return "java"
    if os.path.exists(os.path.join(clone_dir, "go.mod")):
        return "go"
    return None

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 sast_scan.py <repo_url> [language]")
        sys.exit(1)

    repo_url = sys.argv[1]
    language = sys.argv[2] if len(sys.argv) == 3 else None
    clone_dir = "cloned_repo"

    print(f"Cloning {repo_url}...")
    try:
        shutil.rmtree(clone_dir, ignore_errors=True)
        subprocess.run(["git", "clone", repo_url, clone_dir], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e.stderr.decode()}")
        sys.exit(1)

    if language is None:
        print("No language specified, attempting to auto-detect...")
        language = detect_project_type(clone_dir)
        if language:
            print(f"Detected {language.capitalize()} project.")
        else:
            print("Could not determine project type. Running with default rules.")
    else:
        print(f"Language specified: {language.capitalize()}")

    semgrep_configs = ["p/owasp-top-ten"]
    if language == "java":
        print("Adding Java ruleset.")
        semgrep_configs.append("p/java")
    elif language == "go":
        print("Adding Go ruleset.")
        semgrep_configs.append("p/go")

    semgrep_command = ["sast_env/bin/semgrep", "scan", "--json"]
    for config in semgrep_configs:
        semgrep_command.extend(["--config", config])
    semgrep_command.append(clone_dir)

    print(f"Running Semgrep scan with rules: {', '.join(semgrep_configs)}...")
    semgrep_process = subprocess.run(
        semgrep_command,
        capture_output=True,
        text=True
    )

    if semgrep_process.returncode != 0:
        print(f"Error running Semgrep. Exit code: {semgrep_process.returncode}")
        print(f"Stdout: {semgrep_process.stdout}")
        print(f"Stderr: {semgrep_process.stderr}")
        sys.exit(1)

    try:
        semgrep_output = json.loads(semgrep_process.stdout)
    except json.JSONDecodeError:
        print("Error parsing Semgrep JSON output.")
        print(f"Stdout: {semgrep_process.stdout}")
        sys.exit(1)

    print("\n--- SAST Vulnerability Report ---")
    if not semgrep_output["results"]:
        print("No vulnerabilities found.")
    else:
        for result in semgrep_output["results"]:
            print(f"Path: {result['path']}:{result['start']['line']}")
            print(f"Rule ID: {result['check_id']}")
            print(f"Severity: {result['extra']['severity']}")
            print(f"Message: {result['extra']['message']}")
            print("Vulnerable Code:")
            print(result['extra']['lines'])
            print("---")

    # Clean up the cloned repository
    shutil.rmtree(clone_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
