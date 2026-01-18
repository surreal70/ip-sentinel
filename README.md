# IP Intelligence Analyzer (IP-ManA)

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)

A comprehensive Python console application for gathering intelligence about IP addresses through multiple specialized analysis modules. IP-ManA combines local network analysis, internet-based lookups, and enterprise application integration to provide a complete picture of any IP address.

## 🛠️ Technology Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)
![Pytest](https://img.shields.io/badge/Pytest-0A9EDC?style=flat-square&logo=pytest&logoColor=white)
![Hypothesis](https://img.shields.io/badge/Hypothesis-Property_Based_Testing-orange?style=flat-square)
![Nmap](https://img.shields.io/badge/Nmap-Network_Scanner-blue?style=flat-square)
![JSON](https://img.shields.io/badge/JSON-000000?style=flat-square&logo=json&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white)

## Features

### 🎯 Core Capabilities

- **Modular Architecture**: Four specialized analysis modules for comprehensive IP intelligence
  - **Module 1 (Classification)**: RFC-compliant IP address classification
  - **Module 2 (Local Info)**: Network scanning, MAC discovery, SSL analysis
  - **Module 3 (Internet Info)**: WHOIS, geolocation, reputation checking
  - **Module 4 (Applications)**: Enterprise system integration (NetBox, CheckMK, OpenVAS)
- **Multiple Output Formats**: Human-readable console, JSON, and HTML output
- **Flexible Reporting Modes**: Dense (data only), Full (all tests), Full-Error (with errors)
- **Persistent Storage**: SQLite database for historical analysis and tracking
- **Enterprise Integration**: Plugin architecture for IPAM, monitoring, and security tools
- **IPv4 and IPv6 Support**: Full support for both IP address versions

### 📦 Key Dependencies

| Library | Purpose | License |
|---------|---------|---------|
| ![netaddr](https://img.shields.io/badge/netaddr-IP_Handling-blue?style=flat-square) | IP address manipulation | BSD-3-Clause |
| ![ipwhois](https://img.shields.io/badge/ipwhois-WHOIS_Lookup-blue?style=flat-square) | WHOIS and ASN queries | BSD-2-Clause |
| ![python-nmap](https://img.shields.io/badge/python--nmap-Network_Scanning-blue?style=flat-square) | Network scanning wrapper | GPL-3.0 |
| ![sslyze](https://img.shields.io/badge/sslyze-SSL_Analysis-blue?style=flat-square) | SSL/TLS certificate analysis | AGPL-3.0 |
| ![requests](https://img.shields.io/badge/requests-HTTP_Client-blue?style=flat-square) | API communication | Apache-2.0 |
| ![click](https://img.shields.io/badge/click-CLI_Framework-blue?style=flat-square) | Command-line interface | BSD-3-Clause |

## Requirements

### 🐍 Python Environment

- **Python**: 3.8 or higher (3.10+ recommended)
- **Operating System**: 
  - ![Linux](https://img.shields.io/badge/Linux-Supported-success?style=flat-square&logo=linux&logoColor=white)
  - ![macOS](https://img.shields.io/badge/macOS-Supported-success?style=flat-square&logo=apple&logoColor=white)
  - ![Windows](https://img.shields.io/badge/Windows-Supported-success?style=flat-square&logo=windows&logoColor=white)
- **Virtual Environment**: Strongly recommended for isolation

### 🔧 External Tools (Optional)

- **nmap**: For network scanning (Module 2)
  - ![Nmap](https://img.shields.io/badge/nmap-Required_for_Module_2-orange?style=flat-square)
- **Root/Administrator privileges**: For some nmap features

## Installation

### Quick Start

1. **Clone the repository**:
```bash
git clone <repository-url>
cd ip-intelligence-analyzer
```

2. **Create and activate a virtual environment**:
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Install the package**:
```bash
# Development mode (recommended for development)
pip install -e .

# Or standard installation
pip install .
```

5. **Verify installation**:
```bash
ip-mana --version
ip-mana --help
```

### Installing External Tools

#### nmap (Required for Module 2 - Local Network Analysis)

**Linux (Debian/Ubuntu)**:
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Linux (RHEL/CentOS/Fedora)**:
```bash
sudo yum install nmap
# or
sudo dnf install nmap
```

**macOS**:
```bash
brew install nmap
```

**Windows**:
Download from [nmap.org](https://nmap.org/download.html) and install.

### Configuration

#### Classification Rules

On first run, IP-ManA creates a default classification configuration file:
```
classifications.json
```

You can customize IP ranges and classifications using CLI commands (see Usage section).

#### Application Module Credentials (Optional)

If you want to use Module 4 (Application Integration), create a credentials file:

```bash
cp config/app_credentials.example.json config/app_credentials.json
```

Edit `config/app_credentials.json` with your actual credentials for NetBox, CheckMK, OpenVAS, etc.

**Important**: Never commit `config/app_credentials.json` to version control!

## Usage

### Basic Commands

**Analyze an IP address** (default: human-readable output, dense mode):
```bash
ip-mana 192.168.1.1
```

**Analyze with JSON output**:
```bash
ip-mana --json 192.168.1.1
```

**Analyze with HTML output**:
```bash
ip-mana --html 192.168.1.1 > report.html
```

**Full reporting mode** (show all tests, including empty results):
```bash
ip-mana --full 192.168.1.1
```

**Full-error mode** (include error messages and timeouts):
```bash
ip-mana --full-err 192.168.1.1
```

### Advanced Usage

**Force internet module** (even for private IPs):
```bash
ip-mana --force-internet 192.168.1.1
# or
ip-mana --force-module3 192.168.1.1
```

**Custom database location**:
```bash
ip-mana --database /path/to/custom.db 192.168.1.1
```

**Disable database storage**:
```bash
ip-mana --no-database 192.168.1.1
```

**Verbose output** (for debugging):
```bash
ip-mana --verbose 192.168.1.1
```

### Module 4: Application Integration

Module 4 requires explicit specification of submodules:

**Query NetBox IPAM**:
```bash
ip-mana --netbox 192.168.1.1
```

**Query CheckMK monitoring**:
```bash
ip-mana --checkmk 192.168.1.1
```

**Query OpenVAS vulnerability scanner**:
```bash
ip-mana --openvas 192.168.1.1
```

**Query multiple application modules**:
```bash
ip-mana --netbox --checkmk --openvas 192.168.1.1
```

**Specify custom credentials file**:
```bash
ip-mana --credentials /path/to/credentials.json --netbox 192.168.1.1
```

### Classification Management

**Add a custom classification**:
```bash
ip-mana --add-classification "Custom Range" 10.50.0.0/16 "My custom network" "module2,module3"
```

**Delete a classification**:
```bash
ip-mana --delete-classification "Custom Range"
```

**List all classifications**:
```bash
ip-mana --list-classifications
```

### Examples

**Analyze a public IP with full details**:
```bash
ip-mana --full --json 8.8.8.8 > google-dns-analysis.json
```

**Scan local network device with all modules**:
```bash
ip-mana --full-err --netbox --checkmk 192.168.1.100
```

**Quick check of multiple IPs** (using shell loop):
```bash
for ip in 192.168.1.{1..10}; do
    echo "Analyzing $ip..."
    ip-mana --dense $ip
done
```

**Analyze IPv6 address**:
```bash
ip-mana 2001:4860:4860::8888
```

### Output Format Examples

**Human-Readable Output** (default):
```
IP Intelligence Analysis Report
================================
IP Address: 192.168.1.1
IP Version: IPv4
Scan Time: 2026-01-18 15:30:45

Classification Results:
- Private Network (RFC 1918)
- Qualifies for: Module 2 (Local Info)

Local Information:
- Reachable: Yes
- MAC Address: 00:11:22:33:44:55 (Vendor: Example Corp)
- Open Ports: 22, 80, 443
...
```

**JSON Output** (`--json`):
```json
{
  "ip_address": "192.168.1.1",
  "ip_version": 4,
  "scan_timestamp": "2026-01-18T15:30:45",
  "classifications": [...],
  "local_info": {...},
  "internet_info": {...}
}
```

**HTML Output** (`--html`):
Generates a styled HTML report with tables and formatting.

## Development

### 🚀 Setting Up Development Environment

1. **Clone and setup**:
```bash
git clone <repository-url>
cd ip-intelligence-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

2. **Install development dependencies**:
```bash
pip install pytest hypothesis black flake8 isort
```

### ✨ Code Quality

This project follows **PEP 8** standards and uses automated code formatting:

![Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)
![Flake8](https://img.shields.io/badge/linting-flake8-blue?style=flat-square)
![isort](https://img.shields.io/badge/imports-isort-blue?style=flat-square)

**Format code**:
```bash
black src/ tests/
```

**Sort imports**:
```bash
isort src/ tests/
```

**Lint code**:
```bash
flake8 src/ tests/
```

**Run all quality checks**:
```bash
black --check src/ tests/
isort --check src/ tests/
flake8 src/ tests/
```

### 🧪 Testing

The project uses a dual testing approach:
- **Unit Tests**: Specific examples and edge cases
- **Property-Based Tests**: Universal properties using Hypothesis

![Pytest](https://img.shields.io/badge/testing-pytest-0A9EDC?style=flat-square&logo=pytest&logoColor=white)
![Hypothesis](https://img.shields.io/badge/PBT-hypothesis-orange?style=flat-square)
![Coverage](https://img.shields.io/badge/coverage-232_tests-success?style=flat-square)

**Run all tests**:
```bash
pytest
```

**Run specific test categories**:
```bash
# Unit tests only
pytest tests/unit/

# Property-based tests only
pytest tests/property/

# Integration tests only
pytest tests/integration/
```

**Run with coverage**:
```bash
pytest --cov=ip_mana --cov-report=html
```

**Run specific test**:
```bash
pytest tests/unit/test_classification_module.py -v
```

**Run property tests with more examples**:
```bash
pytest tests/property/ --hypothesis-show-statistics
```

### Project Structure

```
ip-intelligence-analyzer/
├── src/ip_mana/              # Main application code
│   ├── __init__.py
│   ├── cli.py                # Command-line interface
│   ├── analyzer.py           # Main controller
│   ├── ip_handler.py         # IP address handling
│   ├── config.py             # Configuration management
│   ├── modules/              # Analysis modules
│   │   ├── classification.py # Module 1
│   │   ├── local_info.py     # Module 2
│   │   ├── internet_info.py  # Module 3
│   │   └── application.py    # Module 4
│   ├── formatters/           # Output formatters
│   │   ├── base.py
│   │   ├── human.py
│   │   ├── json.py
│   │   └── html.py
│   └── database/             # Database layer
│       └── manager.py
├── tests/                    # Test suite
│   ├── unit/                 # Unit tests
│   ├── property/             # Property-based tests
│   └── integration/          # Integration tests
├── docs/                     # Documentation
│   ├── LICENSE_ANALYSIS.md   # License compatibility analysis
│   └── LICENSE_RECOMMENDATION.md
├── config/                   # Configuration files
│   ├── app_credentials.json  # User credentials (gitignored)
│   └── app_credentials.example.json
├── LICENSE                   # MIT License
├── NOTICE                    # Third-party attributions
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── pyproject.toml           # Project configuration
└── setup.py                 # Package setup
```

### Adding New Features

1. **Create a feature branch**:
```bash
git checkout -b feature/my-new-feature
```

2. **Write tests first** (TDD approach):
```bash
# Create test file
touch tests/unit/test_my_feature.py
# Write tests
# Run tests (they should fail)
pytest tests/unit/test_my_feature.py
```

3. **Implement the feature**:
```bash
# Create implementation file
touch src/ip_mana/my_feature.py
# Implement feature
# Run tests (they should pass)
pytest tests/unit/test_my_feature.py
```

4. **Ensure code quality**:
```bash
black src/ tests/
isort src/ tests/
flake8 src/ tests/
pytest
```

5. **Commit and push**:
```bash
git add .
git commit -m "Add my new feature"
git push origin feature/my-new-feature
```

## License

![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 📜 Third-Party Dependencies

This software uses several open source packages with different licenses:

| Dependency | License | Type |
|------------|---------|------|
| netaddr | ![BSD-3](https://img.shields.io/badge/BSD--3--Clause-blue?style=flat-square) | Permissive |
| ipwhois | ![BSD-2](https://img.shields.io/badge/BSD--2--Clause-blue?style=flat-square) | Permissive |
| netifaces | ![MIT](https://img.shields.io/badge/MIT-green?style=flat-square) | Permissive |
| requests | ![Apache-2.0](https://img.shields.io/badge/Apache--2.0-blue?style=flat-square) | Permissive |
| click | ![BSD-3](https://img.shields.io/badge/BSD--3--Clause-blue?style=flat-square) | Permissive |
| colorama | ![BSD-3](https://img.shields.io/badge/BSD--3--Clause-blue?style=flat-square) | Permissive |
| python-nmap | ![GPL-3.0](https://img.shields.io/badge/GPL--3.0-orange?style=flat-square) | Copyleft ⚠️ |
| sslyze | ![AGPL-3.0](https://img.shields.io/badge/AGPL--3.0-orange?style=flat-square) | Copyleft ⚠️ |

**Important**: While this project is MIT-licensed, users must comply with the GPL-3.0 and AGPL-3.0 licenses when using python-nmap and sslyze. These are used as external library dependencies and do not affect the licensing of this software itself.

### 📋 License Documentation

For detailed license analysis and compatibility information, see:
- [LICENSE](LICENSE) - Full MIT license text
- [NOTICE](NOTICE) - Third-party software notices and attributions
- [docs/LICENSE_ANALYSIS.md](docs/LICENSE_ANALYSIS.md) - Comprehensive license compatibility analysis

## Architecture

The application consists of four main analysis modules:

### Module 1: Classification Module
Categorizes IP addresses based on RFC standards and custom rules:
- RFC 1918 private networks
- Multicast addresses
- Localhost and loopback
- Reserved ranges
- Custom user-defined classifications

Determines which other modules should run based on IP classification.

### Module 2: Local Information Module
Gathers network information from the local environment:
- **Reachability**: Ping tests
- **MAC Discovery**: ARP table lookup and vendor identification
- **Network Scanning**: Nmap discovery, OS detection, port scanning
- **SSL/TLS Analysis**: Certificate inspection using sslyze
- **Traceroute**: Multiple methods (ICMP, TCP, UDP)
- **DNS**: Reverse DNS lookup against local resolver

### Module 3: Internet Information Module
Queries external services for public IP intelligence:
- **WHOIS**: Domain and IP registration information
- **Geolocation**: Physical location data
- **ASN**: Autonomous System Number and ownership
- **Reputation**: Spam lists, DNS blocklists, CrowdSec database
- **Reverse DNS**: Multiple internet resolvers (Cloudflare, Google)
- **Hackertarget API**: Additional reverse lookup data

### Module 4: Application Integration Module
Interfaces with enterprise applications (requires explicit activation):
- **NetBox**: IPAM system queries (IP addresses, prefixes, devices, VLANs)
- **CheckMK**: Monitoring system data (host info, services, alerts)
- **OpenVAS**: Vulnerability assessment (scan results, CVEs, threats)
- **OpenITCockpit**: IT management (planned for future release)
- **Infoblox**: DNS/DHCP system (planned for future release)

### Data Flow

```
User Input (IP Address)
         ↓
   Classification Module (Module 1)
         ↓
    Determines qualified modules
         ↓
   ┌─────┴─────┬─────────┬──────────┐
   ↓           ↓         ↓          ↓
Module 2   Module 3  Module 4   Database
(Local)   (Internet) (Apps)     Storage
   ↓           ↓         ↓          ↓
   └─────┬─────┴─────────┴──────────┘
         ↓
   Result Aggregation
         ↓
   Output Formatter
         ↓
   Human/JSON/HTML Output
```

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow PEP 8** coding standards
3. **Write tests** for new functionality (both unit and property tests)
4. **Update documentation** as needed
5. **Run the full test suite** before submitting
6. **Submit a pull request** with a clear description

### Contribution Checklist

- [ ] Code follows PEP 8 standards
- [ ] All tests pass (`pytest`)
- [ ] New features have tests
- [ ] Documentation is updated
- [ ] Commit messages are clear and descriptive
- [ ] No sensitive data in commits

## Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'ip_mana'`
**Solution**: Install the package with `pip install -e .`

**Issue**: `nmap: command not found`
**Solution**: Install nmap (see Installation section)

**Issue**: `Permission denied` when running nmap scans
**Solution**: Some nmap features require root/administrator privileges. Run with `sudo` on Linux/macOS.

**Issue**: Application module returns no data
**Solution**: Check `config/app_credentials.json` for correct credentials and URLs.

**Issue**: Tests fail with timeout errors
**Solution**: Some tests require network access. Check your internet connection.

**Issue**: SSL certificate warnings
**Solution**: This is normal for self-signed certificates. Use `--no-verify-ssl` flag if needed (not implemented yet).

### Getting Help

- **Documentation**: See `docs/` directory
- **Issues**: Report bugs on GitHub Issues
- **Questions**: Open a discussion on GitHub Discussions

## Performance Considerations

- **Module 2 (Local)**: Can be slow for comprehensive nmap scans
- **Module 3 (Internet)**: Depends on external API response times
- **Module 4 (Applications)**: Depends on enterprise system performance
- **Database**: SQLite is fast for single-user scenarios
- **Parallel Execution**: Modules run sequentially by design for reliability

### Optimization Tips

1. Use `--dense` mode for faster output
2. Disable database with `--no-database` if not needed
3. Skip slow modules if not required
4. Use JSON output for programmatic processing

## Security Considerations

- **Credentials**: Never commit `config/app_credentials.json`
- **Network Scanning**: Ensure you have permission to scan networks
- **External APIs**: Be aware of rate limits and terms of service
- **SSL Verification**: Always verify SSL certificates in production
- **Database**: Protect database files containing scan history

## Roadmap

### 🎯 Current Version (0.3.1)
- ✅ Core modules 1-3 implemented
- ✅ Application module with NetBox, CheckMK, OpenVAS
- ✅ Multiple output formats
- ✅ Property-based testing
- ✅ Comprehensive documentation

### 🚀 Planned Features
- [ ] OpenITCockpit submodule (Module 4)
- [ ] Infoblox submodule (Module 4)
- [ ] Web interface
- [ ] REST API
- [ ] Scheduled scanning
- [ ] Alert notifications
- [ ] Export to additional formats (PDF, CSV)
- [ ] Plugin system for custom modules

## ❓ Frequently Asked Questions

**Q: Do I need root privileges to run IP-ManA?**
A: No, but some nmap features in Module 2 require root/administrator privileges.

**Q: Can I analyze multiple IPs at once?**
A: Currently, one IP per invocation. Use shell scripts for batch processing.

**Q: Does IP-ManA work offline?**
A: Modules 1 and 2 work offline. Module 3 requires internet. Module 4 requires network access to enterprise systems.

**Q: How is data stored?**
A: In a SQLite database (default: `ip_analysis.db` in current directory).

**Q: Can I customize the classification rules?**
A: Yes, use `--add-classification` and `--delete-classification` commands.

**Q: Is IP-ManA suitable for production use?**
A: Yes, but review security considerations and test thoroughly in your environment.

**Q: What about IPv6 support?**
A: Full IPv6 support is included in all modules.

## Acknowledgments

### 🙏 Open Source Libraries

This project uses several excellent open source libraries:

| Library | Purpose | License |
|---------|---------|---------|
| [netaddr](https://github.com/netaddr/netaddr) | IP address manipulation | BSD-3-Clause |
| [ipwhois](https://github.com/secynic/ipwhois) | WHOIS and ASN lookups | BSD-2-Clause |
| [python-nmap](https://github.com/nmmapper/python3-nmap) | Network scanning wrapper | GPL-3.0 |
| [sslyze](https://github.com/nabla-c0d3/sslyze) | SSL/TLS analysis | AGPL-3.0 |
| [requests](https://github.com/psf/requests) | HTTP client | Apache-2.0 |
| [click](https://github.com/pallets/click) | CLI framework | BSD-3-Clause |
| [hypothesis](https://github.com/HypothesisWorks/hypothesis) | Property-based testing | MPL-2.0 |

See [NOTICE](NOTICE) for complete attribution and [docs/LICENSE_ANALYSIS.md](docs/LICENSE_ANALYSIS.md) for license details.

---

<div align="center">

**Made with ❤️ for network administrators and security professionals**

![Python](https://img.shields.io/badge/Made%20with-Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-red?style=flat-square)

</div>