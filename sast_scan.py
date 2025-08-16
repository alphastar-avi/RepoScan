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

def scan_repo(repo_url, language=None):
    clone_dir = "cloned_repo"

    # Redirect print statements to stderr when called as a module
    original_stdout = sys.stdout
    if __name__ != '__main__':
        sys.stdout = sys.stderr

    try:
        print(f"Cloning {repo_url}...", file=sys.stderr)
        shutil.rmtree(clone_dir, ignore_errors=True)
        subprocess.run(["git", "clone", repo_url, clone_dir], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e.stderr.decode()}", file=sys.stderr)
        if __name__ != '__main__':
            sys.stdout = original_stdout # Restore stdout before returning
        return {"error": f"Error cloning repository: {e.stderr.decode()}"}

    if language is None:
        print("No language specified, attempting to auto-detect...", file=sys.stderr)
        language = detect_project_type(clone_dir)
        if language:
            print(f"Detected {language.capitalize()} project.", file=sys.stderr)
        else:
            print("Could not determine project type. Running with default rules.", file=sys.stderr)
    else:
        print(f"Language specified: {language.capitalize()}", file=sys.stderr)

    semgrep_configs = ["p/owasp-top-ten"]
    if language == "java":
        print("Adding Java ruleset.", file=sys.stderr)
        semgrep_configs.append("p/java")
    elif language == "go":
        print("Adding Go ruleset.", file=sys.stderr)
        semgrep_configs.append("p/go")

    semgrep_command = ["sast_env/bin/semgrep", "scan", "--json"]
    for config in semgrep_configs:
        semgrep_command.extend(["--config", config])
    semgrep_command.append(clone_dir)

    print(f"Running Semgrep scan with rules: {', '.join(semgrep_configs)}...", file=sys.stderr)
    semgrep_process = subprocess.run(
        semgrep_command,
        capture_output=True,
        text=True
    )

    # Clean up the cloned repository
    shutil.rmtree(clone_dir, ignore_errors=True)

    if semgrep_process.returncode != 0:
        print(f"Error running Semgrep. Exit code: {semgrep_process.returncode}", file=sys.stderr)
        print(f"Stdout: {semgrep_process.stdout}", file=sys.stderr)
        print(f"Stderr: {semgrep_process.stderr}", file=sys.stderr)
        if __name__ != '__main__':
            sys.stdout = original_stdout # Restore stdout before returning
        return {"error": f"Error running Semgrep. Exit code: {semgrep_process.returncode}", "stdout": semgrep_process.stdout, "stderr": semgrep_process.stderr}

    try:
        semgrep_output = json.loads(semgrep_process.stdout)
    except json.JSONDecodeError:
        print("Error parsing Semgrep JSON output.", file=sys.stderr)
        print(f"Stdout: {semgrep_process.stdout}", file=sys.stderr)
        if __name__ != '__main__':
            sys.stdout = original_stdout # Restore stdout before returning
        return {"error": "Error parsing Semgrep JSON output.", "stdout": semgrep_process.stdout}

    # Restore stdout before printing final JSON output
    if __name__ != '__main__':
        sys.stdout = original_stdout

    return semgrep_output

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 sast_scan.py <repo_url> [language]")
        sys.exit(1)

    repo_url = sys.argv[1]
    language = sys.argv[2] if len(sys.argv) == 3 else None
    
    results = scan_repo(repo_url, language)

    if "error" in results:
        print(f"Error: {results['error']}")
        if "stdout" in results:
            print(f"Semgrep Stdout: {results['stdout']}")
        if "stderr" in results:
            print(f"Semgrep Stderr: {results['stderr']}")
        sys.exit(1)

    print("\n--- SAST Vulnerability Report ---")
    if not results["results"]:
        print("No vulnerabilities found.")
    else:
        for result in results["results"]:
            print(f"Path: {result['path']}:{result['start']['line']}")
            print(f"Rule ID: {result['check_id']}")
            print(f"Severity: {result['extra']['severity']}")
            print(f"Message: {result['extra']['message']}")
            print("Vulnerable Code:")
            print(result['extra']['lines'])
            print("---")