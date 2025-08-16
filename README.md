# RepoScan

A simple SAST scanner that uses `semgrep` to find security vulnerabilities in your code.

## Supported Languages

- Java
- Go

## Usage

To scan a repository, simply run the following command:

```bash
python3 sast_scan.py <repository_url> [language]
```

If the language is not specified, the script will try to auto-detect it.

### Example

```bash
python3 sast_scan.py https://github.com/some/vulnerable-java-project java
```
