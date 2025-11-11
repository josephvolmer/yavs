package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os/exec"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

// Hardcoded credentials
const (
	APIKey     = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
	DBPassword = "admin123"
)

// SQL Injection vulnerability
func getUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	db, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(localhost:3306)/mydb", DBPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Unsafe: SQL injection
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	fmt.Fprintf(w, "User: %s", username)
}

// Command Injection vulnerability
func executeCommand(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")

	// Unsafe: command injection
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(out)
}

// Path Traversal vulnerability
func readFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// Unsafe: path traversal
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Write(data)
}

// XSS vulnerability
func search(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	// Unsafe: reflected XSS
	fmt.Fprintf(w, "<h1>Search Results for: %s</h1>", query)
}

// Insecure random for security purposes
func generateToken() string {
	// Unsafe: math/rand is not cryptographically secure
	return fmt.Sprintf("%d", rand.Intn(999999))
}

// Weak cryptography
func weakHash(password string) string {
	// Unsafe: MD5 is cryptographically broken
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Unsafe HTTP client (no TLS verification)
func makeInsecureRequest(url string) error {
	// Unsafe: disabled TLS verification
	http.DefaultTransport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/user", getUser).Methods("GET")
	r.HandleFunc("/execute", executeCommand).Methods("GET")
	r.HandleFunc("/read", readFile).Methods("GET")
	r.HandleFunc("/search", search).Methods("GET")

	// Log API key (unsafe)
	fmt.Printf("Starting server with API Key: %s\n", APIKey)

	// Unsafe: binding to all interfaces
	http.ListenAndServe("0.0.0.0:8080", r)
}
