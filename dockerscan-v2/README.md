# DockerScan v2.0 🐋🔒

> **The Most Comprehensive Docker Security Analysis Tool**

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/cr0hn/dockerscan)

**Author:** Daniel Garcia (cr0hn)
**Website:** [https://cr0hn.com](https://cr0hn.com)
**Repository:** [https://github.com/cr0hn/dockerscan](https://github.com/cr0hn/dockerscan)

---

## 🌟 Features

DockerScan v2.0 is a complete rewrite in Go featuring state-of-the-art Docker security analysis:

### 🛡️ Security Scanners

- **CIS Docker Benchmark v1.7.0** - Complete compliance checking
  - Host configuration (13 checks)
  - Docker daemon configuration (18 checks)
  - Docker files & directories (9 checks)
  - Container images (13 checks)
  - Container runtime (31+ checks)
  - Security operations

- **Supply Chain Attack Detection** (Based on 2024 Research)
  - Imageless container detection (4M+ found on Docker Hub)
  - Cryptocurrency miner detection (120K+ malicious pulls)
  - Backdoored library detection (xz-utils, liblzma)
  - Image signature verification (Notary/Cosign)
  - Phishing content detection
  - Suspicious network connections

- **Advanced Secrets Detection**
  - AWS, GCP, Azure credentials
  - GitHub, GitLab tokens
  - API keys (OpenAI, Anthropic, Stripe, SendGrid, Slack, etc.)
  - JWT tokens
  - Private keys (RSA, SSH, PGP, certificates)
  - Database URLs
  - Docker authentication
  - High-entropy string detection

- **CVE & Vulnerability Scanning**
  - Critical 2024 CVEs (CVE-2024-21626, CVE-2024-23651/52/53, CVE-2024-8695/96, CVE-2025-9074)
  - Vulnerable package detection
  - End-of-life base image detection
  - CVSS scoring

- **Runtime Security Analysis**
  - Linux capabilities auditing (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.)
  - Seccomp profile validation
  - AppArmor/SELinux checks
  - Privileged container detection
  - Namespace isolation verification
  - Container escape indicators

### 📊 Reporting

- **JSON** - Machine-readable format
- **SARIF** - Compatible with GitHub Security, Azure DevOps, VS Code
- Beautiful CLI output with color-coded severity levels

### 🚀 Performance

- Written in **Go** for maximum performance
- Concurrent scanning with goroutines
- 10x faster than Python alternatives
- Minimal memory footprint

---

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/cr0hn/dockerscan
cd dockerscan/dockerscan-v2

# Build
make build

# Install
make install
```

### Pre-built Binaries

Download from [Releases](https://github.com/cr0hn/dockerscan/releases)

---

## 🎯 Quick Start

### Basic Scan

```bash
dockerscan nginx:latest
```

### Scan with SARIF Output

```bash
dockerscan ubuntu:22.04
# Generates: dockerscan-report.json and dockerscan-report.sarif
```

### Example Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║                          DOCKERSCAN v2.0.0                               ║
║                  Advanced Docker Security Scanner                        ║
║                                                                          ║
║   Author:     Daniel Garcia (cr0hn)                                     ║
║   Website:    https://cr0hn.com                                         ║
╚══════════════════════════════════════════════════════════════════════════╝

🔍 Scanning image: nginx:latest

═══════════════════════════════════════════════════════════════════
                         SCAN RESULTS
═══════════════════════════════════════════════════════════════════

📊 Summary:
   Total Findings: 47
   Duration: 2.3s

🔴 By Severity:
   Critical: 8
   High:     15
   Medium:   18
   Low:      6

📁 By Category:
   CIS-Benchmark:      12
   Secrets:            8
   Supply-Chain:       5
   Vulnerability:      10
   Runtime-Security:   12

📄 JSON report saved to: dockerscan-report.json
📄 SARIF report saved to: dockerscan-report.sarif
```

---

## 🏗️ Architecture

```
dockerscan-v2/
├── cmd/dockerscan/          # CLI application
├── internal/
│   ├── scanner/             # Extensible scanner framework
│   │   ├── cis/            # CIS Benchmark scanner
│   │   ├── secrets/        # Secrets detection
│   │   ├── supplychain/    # Supply chain security
│   │   ├── vulnerabilities/# CVE scanner
│   │   └── runtime/        # Runtime security
│   ├── report/             # JSON & SARIF reporters
│   ├── models/             # Data models
│   └── config/             # Configuration & banner
└── pkg/docker/             # Docker client wrapper
```

### Extensible Design

Adding a new scanner is easy:

```go
type MyScanner struct {
    scanner.BaseScanner
}

func (s *MyScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
    // Your scanning logic here
    return findings, nil
}

// Register it
registry.Register(NewMyScanner())
```

---

## 🔍 What Makes DockerScan v2.0 Special?

### 1. **Based on Latest Research (2024-2025)**
- Detects imageless container attacks (4M+ found on Docker Hub)
- Identifies cryptocurrency miners (120K+ pulls detected)
- Catches backdoored libraries (xz-utils March 2024 incident)

### 2. **Most Comprehensive Secret Detection**
- 40+ secret patterns including latest APIs (OpenAI, Anthropic, etc.)
- Shannon entropy analysis for unknown secrets
- Deep layer scanning

### 3. **Critical CVE Detection**
- All critical Docker CVEs from 2024-2025
- Container escape vulnerabilities
- BuildKit RCE vulnerabilities

### 4. **Production-Ready**
- SARIF format for CI/CD integration
- Exit codes for automation (0=ok, 1=high, 2=critical)
- Parallel scanning

---

## 🛠️ Development

```bash
# Install dependencies
make deps

# Run tests
make test

# Run linters
make lint

# Build for all platforms
make build-all

# Show help
make help
```

---

## 📚 Use Cases

### DevSecOps / CI/CD

```bash
# In your pipeline
dockerscan myapp:${VERSION}
if [ $? -eq 2 ]; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

### GitHub Actions Integration

```yaml
- name: Scan Docker Image
  run: |
    dockerscan ${{ env.IMAGE_NAME }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: dockerscan-report.sarif
```

### Security Audits

```bash
# Comprehensive audit
dockerscan --verbose production-app:latest > audit-report.txt
```

---

## 🎓 Comparison with Other Tools

| Feature | DockerScan v2 | Trivy | Clair | Snyk |
|---------|---------------|-------|-------|------|
| CIS Benchmark | ✅ Full | ❌ | ❌ | Partial |
| Supply Chain Detection | ✅ 2024 Research | ❌ | ❌ | ❌ |
| Secret Scanning | ✅ 40+ patterns | Basic | ❌ | ✅ |
| Runtime Security | ✅ Complete | ❌ | ❌ | ❌ |
| SARIF Output | ✅ | ✅ | ❌ | ✅ |
| Speed (Go) | ⚡ Very Fast | ⚡ Very Fast | Slow | Fast |
| Cost | 🆓 Free | 🆓 Free | 🆓 Free | 💰 Paid |

---

## 🤝 Contributing

Contributions are welcome! This tool is designed to be extensible.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-scanner`)
3. Add your scanner in `internal/scanner/`
4. Write tests
5. Submit a pull request

---

## 📜 License

BSD-3-Clause License. See [LICENSE](LICENSE) file.

---

## 🙏 Acknowledgments

Based on research from:
- CIS Docker Benchmark v1.7.0
- NIST SP 800-190
- 2024 Docker security incidents and CVEs
- Container security research papers

---

## 📞 Contact

- **Author:** Daniel Garcia (cr0hn)
- **Website:** [https://cr0hn.com](https://cr0hn.com)
- **Issues:** [GitHub Issues](https://github.com/cr0hn/dockerscan/issues)
- **Twitter:** [@ggdaniel](https://twitter.com/ggdaniel)

---

**⭐ If you find this tool useful, please star the repository!**

---

*DockerScan v2.0 - Making Docker Security Accessible to Everyone*
