# RepoScan

A simple SAST scanner that uses `semgrep` to find security vulnerabilities in your code.(Owasp top 10)

<img width="1348" height="1020" alt="Screenshot 2025-08-17 at 4 34 28 AM" src="https://github.com/user-attachments/assets/27ac535d-796b-405f-b464-14ac24e5a8fa" />

## Sample output

```bash
---Path: cloned_repo/VulnerableController.java:33
Rule ID: java.spring.security.injection.tainted-sql-string.tainted-sql-string
Severity: ERROR
Message: User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`connection.PreparedStatement`) or a safe library.
Vulnerable Code:requires login
---
---Path: cloned_repo/VulnerableController.java:34
Rule ID: java.spring.security.audit.spring-sqli.spring-sqli
Severity: WARNING
Message: Detected a string argument from a public method contract in a raw SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
Vulnerable Code:requires login
---
---Path: cloned_repo/VulnerableController.java:50
Rule ID: java.spring.security.injection.tainted-file-path.tainted-file-path
Severity: ERROR
Message: Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
Vulnerable Code:requires login
---
```

## Supported rule-set for languages:

- Java
- Go
- can be added as need...

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

## Web Interface

Install the required dependencies:

```bash
pip install -r requirements.txt`
```

Then, run the Flask application:

```bash
python3 app.py
```

Access the web interface in your browser at `:8080/`.
