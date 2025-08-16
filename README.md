# RepoScan

A simple SAST scanner that uses `semgrep` to find security vulnerabilities in your code.

## Supported Languages

- Java
- Go

## Usage (Python Version)

To scan a repository, simply run the following command:

```bash
python3 sast_scan.py <repository_url> [language]
```

If the language is not specified, the script will try to auto-detect it.

### Example (Python Version)

```bash
python3 sast_scan.py https://github.com/some/vulnerable-java-project java
```

## Usage (Go Version)

To scan a repository using the Go version, first build the executable:

```bash
go build -o reposcan sast_scan.go
```

Then run the executable:

```bash
./reposcan <repository_url> [language]
```

If the language is not specified, the tool will try to auto-detect it.

### Example (Go Version)

```bash
./reposcan https://github.com/some/vulnerable-go-project go
```