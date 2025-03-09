# GOSQL

A fast and concurrent SQL Injection vulnerability scanner written in Go. This tool tests URLs for potential SQL injection vulnerabilities by injecting various payloads and checking for error messages indicative of SQLi flaws.

---

## Features

- **Concurrent Scanning**: Leverages Go's goroutines for high-speed scanning.
- **Multiple Injection Patterns**: Tests 30+ SQLi payloads (e.g., `' OR 1=1--`, `UNION SELECT`).
- **Error-Based Detection**: Detects 25+ SQL error patterns (e.g., `ORA-`, `SQL syntax`).
- **JSON Output**: Saves results in structured JSON format.
- **Customizable Depth**: Limits the number of payloads tested per parameter.
- **User-Agent Spoofing**: Randomizes User-Agent headers to avoid detection.

---

## Installation

### Prerequisites
- [Go](https://golang.org/doc/install) (1.16+)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/nando-z/gosql.git
   cd gosql

2. Build and Run :
   
    ```bash
     go build -o gosql
     ./gosql
    ```

    ```bash
    ./gosql -h
    ```
#
<center>Nando-z x Mr Dark</center>
