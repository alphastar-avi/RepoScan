package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SemgrepResult represents a single vulnerability finding from Semgrep
type SemgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Severity string `json:"severity"`
		Message  string `json:"message"`
		Lines    string `json:"lines"`
	} `json:"extra"`
}

// SemgrepOutput represents the overall JSON output from Semgrep
type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
}

// detectProjectType checks for common project files to determine the language
func detectProjectType(cloneDir string) string {
	if _, err := os.Stat(filepath.Join(cloneDir, "pom.xml")); err == nil {
		return "java"
	}
	if _, err := os.Stat(filepath.Join(cloneDir, "build.gradle")); err == nil {
		return "java"
	}
	if _, err := os.Stat(filepath.Join(cloneDir, "go.mod")); err == nil {
		return "go"
	}
	return ""
}

// cloneRepo clones a git repository into a specified directory
func cloneRepo(repoURL, cloneDir string) error {
	// Clean up previous clone if it exists
	if _, err := os.Stat(cloneDir); err == nil {
		os.RemoveAll(cloneDir)
	}

	cmd := exec.Command("git", "clone", repoURL, cloneDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error cloning repository: %s", stderr.String())
	}
	return nil
}

// runSemgrepScan executes Semgrep and returns its JSON output
func runSemgrepScan(cloneDir, language string) ([]byte, error) {
	semgrepConfigs := []string{"p/owasp-top-ten"}
	if language == "java" {
		semgrepConfigs = append(semgrepConfigs, "p/java")
	} else if language == "go" {
		semgrepConfigs = append(semgrepConfigs, "p/go")
	}

	args := []string{"scan", "--json"}
	for _, config := range semgrepConfigs {
		args = append(args, "--config", config)
	}
	args = append(args, cloneDir)

	// Assuming semgrep is in sast_env/bin/semgrep relative to the current working directory
	semgrepPath := "sast_env/bin/semgrep"
	cmd := exec.Command(semgrepPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error running Semgrep: %s, Stderr: %s", err.Error(), stderr.String())
	}

	return stdout.Bytes(), nil
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Println("Usage: go run sast_scan.go <repo_url> [language]")
		os.Exit(1)
	}

	repoURL := os.Args[1]
	language := ""
	if len(os.Args) == 3 {
		language = os.Args[2]
	}

	cloneDir := "cloned_repo"

	fmt.Printf("Cloning %s...\n", repoURL)
	if err := cloneRepo(repoURL, cloneDir); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer os.RemoveAll(cloneDir) // Clean up cloned repo

	if language == "" {
		fmt.Println("No language specified, attempting to auto-detect...")
		language = detectProjectType(cloneDir)
		if language != "" {
			fmt.Printf("Detected %s project.\n", strings.Title(language))
		} else {
			fmt.Println("Could not determine project type. Running with default rules.")
		}
	} else {
		fmt.Printf("Language specified: %s\n", strings.Title(language))
	}

	fmt.Printf("Running Semgrep scan with rules: p/owasp-top-ten")
	if language == "java" {
		fmt.Printf(", p/java")
	} else if language == "go" {
		fmt.Printf(", p/go")
	}
	fmt.Println("...")

	semgrepOutputBytes, err := runSemgrepScan(cloneDir, language)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var semgrepOutput SemgrepOutput
	if err := json.Unmarshal(semgrepOutputBytes, &semgrepOutput); err != nil {
		fmt.Printf("Error parsing Semgrep JSON output: %v\n", err)
		fmt.Printf("Raw Semgrep output: %s\n", string(semgrepOutputBytes))
		os.Exit(1)
	}

	fmt.Println("\n--- SAST Vulnerability Report ---")
	if len(semgrepOutput.Results) == 0 {
		fmt.Println("No vulnerabilities found.")
	} else {
		for _, result := range semgrepOutput.Results {
			fmt.Printf("Path: %s:%d\n", result.Path, result.Start.Line)
			fmt.Printf("Rule ID: %s\n", result.CheckID)
			fmt.Printf("Severity: %s\n", result.Extra.Severity)
			fmt.Printf("Message: %s\n", result.Extra.Message)
			fmt.Println("Vulnerable Code:")
			fmt.Println(result.Extra.Lines)
			fmt.Println("---")
		}
	}
}
