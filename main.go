package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// --- Configuration Structure ---

type ServerConfig struct {
	PublicPort       int      `json:"public_port"`       // REQUIRED
	PrivatePort      int      `json:"private_port"`      // REQUIRED
	TargetExecutable string   `json:"target_executable"` // OPTIONAL (If empty, Manual Mode)
	TargetArgs       []string `json:"target_args"`       // Optional
	UseHTTPS         bool     `json:"use_https"`         // Optional
	CertFile         string   `json:"cert_file"`         // Required if use_https is true
	KeyFile          string   `json:"key_file"`          // Required if use_https is true
	MaxRequestBytes  int64    `json:"max_request_bytes"` // Optional (default: 10MB)
	HealthCheckRetries int    `json:"health_check_retries"` // Optional (default: 30)
	HealthCheckInterval int   `json:"health_check_interval"` // Optional in seconds (default: 1)
}

type Config struct {
	Server  ServerConfig      `json:"server"`
	Headers map[string]string `json:"headers"`
}

var config Config

// Security: Whitelist of allowed executables
var allowedExecutables = map[string]bool{
	"node":     true,
	"python":   true,
	"python3":  true,
	"dotnet":   true,
	"java":     true,
	"ruby":     true,
	"php":      true,
}

func main() {
	// 1. Strict Argument Check
	if len(os.Args) < 2 {
		fmt.Println("❌ Error: Missing configuration file.")
		fmt.Println("Usage: ./SecureGate <path-to-config.json>")
		os.Exit(1)
	}

	configPath := os.Args[1]
	
	// Security: Validate config path
	if err := validateConfigPath(configPath); err != nil {
		fmt.Printf("❌ Security Error: %v\n", err)
		os.Exit(1)
	}
	
	loadConfig(configPath)
	validateConfig()

	// 2. Mode Selection
	if config.Server.TargetExecutable != "" {
		// --- SUPERVISOR MODE ---
		fmt.Println("⚙️  Mode: SUPERVISOR (Launching child process)")
		
		// Security: Validate executable
		if err := validateExecutable(config.Server.TargetExecutable); err != nil {
			fmt.Printf("❌ Security Error: %v\n", err)
			os.Exit(1)
		}
		
		go startChildProcess()
		
		// Wait for child to stabilize with health checks
		fmt.Printf("⏳ Waiting for target to initialize on port %d...\n", config.Server.PrivatePort)
		if !waitForService() {
			fmt.Println("❌ Target service failed to start")
			os.Exit(1)
		}
		fmt.Println("✅ Target service is ready")
	} else {
		// --- MANUAL MODE ---
		fmt.Println("⚙️  Mode: MANUAL (Connecting to existing server)")
		fmt.Printf("⚠️  Ensure your web server is ALREADY running on port %d\n", config.Server.PrivatePort)
	}

	// 3. Start the Proxy
	startProxy()
}

// --- Security Functions ---

func validateConfigPath(path string) error {
	// Prevent path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal detected in config path")
	}
	
	// Ensure it's a JSON file
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		return fmt.Errorf("configuration file must be a .json file")
	}
	
	// Check if file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access config file: %v", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("config path is a directory, not a file")
	}
	
	return nil
}

func validateExecutable(executable string) error {
	// Get base executable name (without path)
	baseName := filepath.Base(executable)
	
	// Remove .exe extension on Windows for comparison
	baseName = strings.TrimSuffix(baseName, ".exe")
	
	// Check against whitelist
	if !allowedExecutables[baseName] {
		return fmt.Errorf("executable '%s' is not in the allowed list. Allowed: node, python, python3, dotnet, java, ruby, php", baseName)
	}
	
	return nil
}

func validateHeaders(headers map[string]string) error {
	for key, value := range headers {
		// Prevent CRLF injection
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid header detected: CRLF characters not allowed")
		}
		
		// Basic header name validation
		if key == "" {
			return fmt.Errorf("empty header name not allowed")
		}
	}
	return nil
}

func waitForService() bool {
	retries := config.Server.HealthCheckRetries
	if retries == 0 {
		retries = 30 // default: 30 attempts
	}
	
	interval := config.Server.HealthCheckInterval
	if interval == 0 {
		interval = 1 // default: 1 second
	}
	
	targetURL := fmt.Sprintf("http://127.0.0.1:%d", config.Server.PrivatePort)
	
	for i := 0; i < retries; i++ {
		client := &http.Client{
			Timeout: time.Second * 2,
		}
		
		resp, err := client.Get(targetURL)
		if err == nil {
			resp.Body.Close()
			return true
		}
		
		time.Sleep(time.Duration(interval) * time.Second)
	}
	
	return false
}

// --- Helper Functions ---

func loadConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("❌ Error opening config file")
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("❌ Error parsing JSON config")
	}
	fmt.Printf("✅ Configuration loaded from %s\n", filename)
}

func validateConfig() {
	if config.Server.PublicPort == 0 || config.Server.PrivatePort == 0 {
		log.Fatal("❌ Configuration Error: 'public_port' and 'private_port' are required.")
	}
	
	// Validate port ranges
	if config.Server.PublicPort < 1 || config.Server.PublicPort > 65535 {
		log.Fatal("❌ Configuration Error: 'public_port' must be between 1 and 65535")
	}
	
	if config.Server.PrivatePort < 1 || config.Server.PrivatePort > 65535 {
		log.Fatal("❌ Configuration Error: 'private_port' must be between 1 and 65535")
	}
	
	if config.Server.UseHTTPS {
		if config.Server.CertFile == "" || config.Server.KeyFile == "" {
			log.Fatal("❌ Configuration Error: HTTPS is true, but 'cert_file' or 'key_file' is missing.")
		}
	}
	
	// Validate headers
	if err := validateHeaders(config.Headers); err != nil {
		log.Fatalf("❌ Configuration Error: %v", err)
	}
	
	// Set default max request bytes if not specified
	if config.Server.MaxRequestBytes == 0 {
		config.Server.MaxRequestBytes = 10 * 1024 * 1024 // 10MB default
	}
}

func startChildProcess() {
	fmt.Printf("🚀 Launching Target: %s\n", config.Server.TargetExecutable)

	cmd := exec.Command(config.Server.TargetExecutable, config.Server.TargetArgs...)

	// Security: Use clean environment with only necessary variables
	// Do NOT pass parent process environment variables
	cmd.Env = []string{
		fmt.Sprintf("PORT=%d", config.Server.PrivatePort),
		fmt.Sprintf("ASPNETCORE_URLS=http://localhost:%d", config.Server.PrivatePort),
		// Add PATH for executable resolution
		fmt.Sprintf("PATH=%s", os.Getenv("PATH")),
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		log.Fatalf("❌ Failed to start target executable")
	}

	// Graceful Shutdown Handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n🛑 Shutting down gracefully...")
		
		// Try graceful shutdown first
		if cmd.Process != nil {
			fmt.Println("⏳ Sending termination signal to child process...")
			cmd.Process.Signal(syscall.SIGTERM)
			
			// Wait up to 5 seconds for graceful shutdown
			done := make(chan error, 1)
			go func() {
				done <- cmd.Wait()
			}()
			
			select {
			case <-done:
				fmt.Println("✅ Child process terminated gracefully")
			case <-time.After(5 * time.Second):
				fmt.Println("⚠️  Graceful shutdown timeout, forcing kill...")
				cmd.Process.Kill()
			}
		}
		os.Exit(0)
	}()

	// Wait for process to complete (if it exits on its own)
	if err := cmd.Wait(); err != nil {
		// Don't log error if it was intentionally killed
		if !strings.Contains(err.Error(), "signal: killed") {
			fmt.Printf("⚠️  Child process exited: %v\n", err)
		}
	}
}

func startProxy() {
	targetURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(config.Server.PrivatePort))
	
	// Check if target is actually reachable before starting proxy
	if config.Server.TargetExecutable == "" {
		checkConnection(targetURL)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
	}

	proxy.ModifyResponse = func(r *http.Response) error {
		// Inject custom headers
		for key, value := range config.Headers {
			r.Header.Set(key, value)
		}
		
		// Remove server identification (security through obscurity)
		r.Header.Del("Server")
		r.Header.Del("X-Powered-By")
		
		return nil
	}

	mux := http.NewServeMux()
	
	// Wrap proxy with request size limiting middleware
	limitedProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security: Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, config.Server.MaxRequestBytes)
		proxy.ServeHTTP(w, r)
	})
	
	mux.Handle("/", limitedProxy)

	addr := ":" + strconv.Itoa(config.Server.PublicPort)
	fmt.Printf("🛡️  Secure Proxy Active: http://localhost%s -> Port %d\n", addr, config.Server.PrivatePort)
	fmt.Printf("📊 Max request size: %d MB\n", config.Server.MaxRequestBytes/(1024*1024))

	var err error
	if config.Server.UseHTTPS {
		// Security: Harden TLS configuration
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		}
		
		server := &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: tlsConfig,
			// Additional security timeouts
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		
		fmt.Println("🔒 TLS Configuration: TLS 1.2+ with secure cipher suites")
		err = server.ListenAndServeTLS(config.Server.CertFile, config.Server.KeyFile)
	} else {
		server := &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		err = server.ListenAndServe()
	}

	if err != nil {
		log.Fatalf("❌ Proxy Server Error")
	}
}

func checkConnection(target *url.URL) {
	fmt.Println("🔍 Checking connection to target server...")
	client := &http.Client{
		Timeout: time.Second * 2,
	}
	
	resp, err := client.Get(target.String())
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not connect to %s. Is your server running?\n", target.String())
	} else {
		resp.Body.Close()
		fmt.Println("✅ Connection successful.")
	}
}