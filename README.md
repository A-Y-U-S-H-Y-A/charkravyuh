# Chakravyuh 🛡️

A lightweight, high-performance reverse proxy and security middleware designed to wrap any web application. Chakravyuh allows you to inject security headers, manage SSL termination, and effectively "move" your web server to a secure, private port while exposing a hardened public interface.

Built in Go with security-first design, it compiles to a single, dependency-free binary for Windows, Linux, and macOS.

## 🚀 Key Features

- **Header Injection**: Automatically injects security headers (HSTS, CSP, X-Frame-Options) to achieve A+ scores on Mozilla Observatory
- **Port Management (Supervisor Mode)**: Launches your web server as a child process, forcing it to run on a private port (via env vars) while Chakravyuh handles public traffic
- **Manual Mode**: Acts as a gateway for already running services on specific ports
- **SSL Termination**: Handles HTTPS/TLS encryption with hardened TLS 1.2+ configuration
- **Security Hardening**: Request size limiting to prevent DoS attacks
- **Cross-Platform**: Works seamlessly on Windows Servers, Linux, and macOS

## 📦 Installation

### Option 1: Build from Source (Recommended)

You need Go installed.

1. Clone the repository
2. Compile the binary for your OS:

**Windows:**
```bash
go build -o Chakravyuh.exe main.go
```

**Linux/macOS:**
```bash
go build -o Chakravyuh main.go
```

## 🏃 Usage

Chakravyuh is entirely configuration-driven. You must provide the path to a JSON configuration file as the only argument.

```bash
# Windows
.\Chakravyuh.exe config.json

# Linux/macOS
./Chakravyuh config.json
```

## ⚙️ Configuration Guide

The configuration file controls the server behavior and headers to be injected. It consists of two main blocks: `server` and `headers`.

### 1. The `server` Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `public_port` | Int | Yes | - | The port Chakravyuh listens on (e.g., 80, 443) |
| `private_port` | Int | Yes | - | The internal port your actual web app is running on |
| `target_executable` | String | No | `""` | **Supervisor Mode:** Path to your app's executable. Must be whitelisted (node, python, python3, dotnet, java, ruby, php).<br>**Manual Mode:** Leave empty `""` to connect to an already running app |
| `target_args` | Array | No | `[]` | Arguments to pass to the executable (e.g., `["server.js"]`) |
| `use_https` | Bool | No | `false` | Set to `true` to enable SSL with hardened TLS 1.2+ configuration |
| `cert_file` | String | If HTTPS | - | Path to `.crt` or `.pem` file |
| `key_file` | String | If HTTPS | - | Path to `.key` file |
| `max_request_bytes` | Int | No | `10485760` | Maximum request body size in bytes (default: 10MB) |
| `health_check_retries` | Int | No | `30` | Number of health check attempts when starting supervised process |
| `health_check_interval` | Int | No | `1` | Seconds between health check attempts |

### 2. The `headers` Block

Define key-value pairs for HTTP headers. These overwrite any headers sent by the backend server.

**Security Note**: Headers are validated to prevent CRLF injection attacks.

## 🔒 Security Features

### Whitelisted Executables
Only these executables are allowed in Supervisor Mode (security against command injection):
- `node`
- `python` / `python3`
- `dotnet`
- `java`
- `ruby`
- `php`

### TLS Hardening
When HTTPS is enabled, Chakravyuh enforces:
- Minimum TLS 1.2
- Strong cipher suites only (AES-GCM)
- Server-preferred cipher suite ordering

### Request Protection
- Maximum request size limits (configurable, default 10MB)
- Read/Write/Idle timeouts to prevent slowloris attacks
- Server fingerprint removal

### Clean Environment
Child processes receive only necessary environment variables, preventing credential leakage from parent process.

## 🛠️ Modes of Operation

### Mode A: Supervisor Mode (Automated)

**Best for:** Binaries, Python scripts, Node.js apps that accept a `PORT` env variable.

Chakravyuh launches your application for you. It sets the `PORT` environment variable to the `private_port` value, forcing your app to listen internally.

```json
{
  "server": {
    "public_port": 80,
    "private_port": 8080,
    "target_executable": "node",
    "target_args": ["server.js"],
    "max_request_bytes": 5242880
  },
  "headers": { }
}
```

### Mode B: Manual Mode (Decoupled)

**Best for:** Docker containers, IIS, complex services, or apps already running.

Chakravyuh assumes your app is already running on `localhost:private_port`. It simply forwards traffic.

```json
{
  "server": {
    "public_port": 80,
    "private_port": 8080,
    "target_executable": ""
  },
  "headers": { }
}
```

## 📝 Example Configurations

An example configuration is sample.json.

## 🔐 Security Best Practices

### Firewall Configuration
- **Allow** inbound traffic on `public_port` (e.g., 80, 443)
- **Block** external access to `private_port` (only localhost should access it)

### Certificate Management
- For HTTPS, ensure your `cert_file` includes the full certificate chain if using Let's Encrypt
- Keep private keys secure with appropriate file permissions (`chmod 600` on Linux)
- Rotate certificates before expiration

### Process Privileges
- On Linux/macOS, if binding to ports 80/443, you may need to run as root initially
- Consider using `setcap` on Linux to allow binding to privileged ports without root:
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' ./Chakravyuh
  ```

### Configuration File Security
- Protect your config file with appropriate permissions
- Never commit config files with credentials to version control
- Validate configuration before deployment

### Request Size Limits
- Adjust `max_request_bytes` based on your application needs
- Smaller limits = better DoS protection
- Consider your largest expected upload size

## ⚠️ Important Notes

### Whitelisted Executables Only
Chakravyuh only allows execution of whitelisted programs (node, python, python3, dotnet, java, ruby, php) to prevent command injection attacks. If you need to run a different executable, you must:
1. Use Manual Mode and start your application separately, OR
2. Modify the source code to add your executable to the whitelist

### Environment Variables
For security, child processes receive a **clean environment** with only these variables:
- `PORT` - Set to your `private_port`
- `ASPNETCORE_URLS` - For .NET applications
- `PATH` - For executable resolution

If your application requires additional environment variables, you'll need to modify the source code or use Manual Mode.

## 📄 License

GNU GPL v3
