# Design Document: IP Intelligence Analyzer

## Overview

The IP Intelligence Analyzer (IP-Sentinel) is a modular Python console application that provides comprehensive intelligence gathering for IP addresses. The system employs a plugin-based architecture with four main analysis modules, flexible output formatting, and persistent data storage. The design emphasizes modularity, extensibility, and robust error handling while supporting both IPv4 and IPv6 addresses.

## Architecture

The application follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Interface Layer                      │
├─────────────────────────────────────────────────────────────┤
│         Application Controller  │  Batch Processor          │
├─────────────────────────────────────────────────────────────┤
│  Module 1    │  Module 2    │  Module 3    │  Module 4     │
│ Classification│ Local Info   │ Internet Info│ App Integration│
├─────────────────────────────────────────────────────────────┤
│  Output Formatter  │  Database Layer  │  Progress Tracker  │
├─────────────────────────────────────────────────────────────┤
│              Core Libraries & External APIs                 │
└─────────────────────────────────────────────────────────────┘
```

### Key Architectural Principles

- **Modular Design**: Each analysis module is independent and can be enabled/disabled
- **Plugin Architecture**: Module 4 submodules are dynamically loadable
- **Separation of Concerns**: Clear boundaries between data collection, processing, and presentation
- **Extensibility**: New modules and output formats can be added without core changes
- **Error Isolation**: Module failures don't affect other modules
- **Batch Processing**: Support for both sequential and parallel processing of multiple IPs
- **Progress Tracking**: Real-time feedback for long-running batch operations

## Components and Interfaces

### Core Components

#### 1. Application Controller (`IPAnalyzer`)
- **Purpose**: Orchestrates the entire analysis workflow
- **Responsibilities**: 
  - Command-line argument parsing and validation
  - Module execution coordination
  - Error handling and logging
  - Result aggregation

```python
class IPAnalyzer:
    def __init__(self, config: Config)
    def analyze(self, ip_address: str) -> AnalysisResult
    def run_modules(self, ip: IPAddress, modules: List[str]) -> Dict[str, ModuleResult]
```

#### 2. IP Address Handler (`IPAddressHandler`)
- **Purpose**: Validates and normalizes IP addresses
- **Libraries**: Python's built-in `ipaddress` module, `netaddr` for advanced operations
- **Responsibilities**:
  - IPv4/IPv6 detection and validation
  - Address normalization and formatting
  - Network calculations (subnet membership, etc.)

```python
class IPAddressHandler:
    def validate_ip(self, ip_str: str) -> IPAddress
    def get_ip_version(self, ip: IPAddress) -> int
    def is_in_subnet(self, ip: IPAddress, subnet: str) -> bool
```

#### 3. Configuration Manager (`ConfigManager`)
- **Purpose**: Manages application configuration and classification rules
- **Storage**: JSON files for classification rules, YAML/INI for application config
- **Responsibilities**:
  - Loading and saving classification definitions
  - Managing module configurations
  - Handling user-defined rules

```python
class ConfigManager:
    def load_classifications(self) -> Dict[str, ClassificationRule]
    def save_classifications(self, rules: Dict[str, ClassificationRule])
    def add_classification(self, rule: ClassificationRule)
    def remove_classification(self, rule_name: str)
```

### Analysis Modules

#### Module 1: Classification Module (`ClassificationModule`)
- **Purpose**: Categorizes IP addresses based on RFC standards and custom rules
- **Data Source**: JSON configuration file with IP range definitions
- **Key Features**:
  - RFC-compliant range detection (private, multicast, localhost, etc.)
  - Custom classification rules
  - Module qualification determination

```python
class ClassificationModule:
    def classify_ip(self, ip: IPAddress) -> List[Classification]
    def get_qualified_modules(self, classifications: List[Classification]) -> List[str]
    def create_default_classifications(self) -> Dict[str, ClassificationRule]
```

#### Module 2: Local Information Module (`LocalInfoModule`)
- **Purpose**: Gathers network information from the local environment
- **External Dependencies**: 
  - `python-nmap` or `python3-nmap` for network scanning
  - `sslyze` for SSL/TLS analysis
  - System utilities: `ping`, `traceroute`
- **Key Features**:
  - Network reachability testing
  - MAC address discovery and vendor identification
  - Port scanning and service detection
  - SSL certificate analysis

```python
class LocalInfoModule:
    def check_reachability(self, ip: IPAddress) -> ReachabilityResult
    def get_mac_address(self, ip: IPAddress) -> Optional[MACAddress]
    def perform_nmap_scan(self, ip: IPAddress) -> NmapResult
    def analyze_ssl_services(self, ip: IPAddress, ports: List[int]) -> List[SSLResult]
```

#### Module 3: Internet Information Module (`InternetInfoModule`)
- **Purpose**: Queries external services for public IP intelligence
- **External Dependencies**:
  - `ipwhois` for WHOIS and ASN lookups
  - `requests` for API calls to external services
  - DNS resolution libraries
- **Key Features**:
  - WHOIS data retrieval
  - Geolocation services
  - Blocklist and reputation checking
  - ASN and network ownership information

```python
class InternetInfoModule:
    def perform_whois_lookup(self, ip: IPAddress) -> WhoisResult
    def get_geolocation(self, ip: IPAddress) -> GeolocationResult
    def check_blocklists(self, ip: IPAddress) -> List[BlocklistResult]
    def get_asn_info(self, ip: IPAddress) -> ASNResult
```

#### Module 4: Application Integration Module (`ApplicationModule`)
- **Purpose**: Interfaces with enterprise applications for internal IP data
- **Architecture**: Plugin-based with dynamic loading
- **Submodules**: NetBox, CheckMK, OpenITCockpit, OpenVAS, Infoblox
- **Key Features**:
  - API authentication handling
  - Standardized result formatting
  - Error handling for external service failures

```python
class ApplicationModule:
    def load_submodule(self, name: str) -> ApplicationSubmodule
    def query_all_enabled(self, ip: IPAddress) -> Dict[str, ApplicationResult]

class ApplicationSubmodule(ABC):
    @abstractmethod
    def query_ip(self, ip: IPAddress) -> ApplicationResult
```

### Data Management

#### Database Layer (`DatabaseManager`)
- **Storage**: SQLite database for scan results and metadata
- **Schema**: Normalized tables for results, scans, and metadata
- **Features**:
  - Automatic schema creation and migration
  - Configurable database location
  - Result deduplication and history tracking

```python
class DatabaseManager:
    def store_scan_result(self, result: AnalysisResult)
    def get_scan_history(self, ip: IPAddress) -> List[ScanRecord]
    def create_database(self, path: str)
```

#### Output Formatter (`OutputFormatter`)
- **Formats**: Human-readable console, JSON, HTML
- **Features**:
  - Template-based formatting
  - Configurable verbosity levels (dense, full, full-err)
  - Structured data export

```python
class OutputFormatter:
    def format_result(self, result: AnalysisResult, format_type: str) -> str
    def set_verbosity(self, mode: VerbosityMode)
```

### Batch Processing Components

#### Batch Processor (`BatchProcessor`)
- **Purpose**: Manages batch analysis of multiple IP addresses from CIDR networks
- **Libraries**: Python's `ipaddress` module for CIDR expansion, `concurrent.futures` for parallel processing
- **Features**:
  - CIDR network expansion with 1024 IP limit validation
  - Sequential and parallel processing modes
  - Progress tracking with overall and per-IP indicators
  - Output file management with sanitized filenames

```python
class BatchProcessor:
    def __init__(self, analyzer: IPAnalyzer, output_folder: str, parallel: bool = False)
    def process_cidr(self, cidr: str) -> BatchResult
    def expand_cidr(self, cidr: str) -> List[IPAddress]
    def validate_batch_size(self, ip_list: List[IPAddress]) -> bool
    def process_ip_list(self, ip_list: List[IPAddress]) -> BatchResult
    def sanitize_filename(self, ip: IPAddress) -> str
```

#### Progress Tracker (`ProgressTracker`)
- **Purpose**: Provides real-time progress feedback for batch operations
- **Features**:
  - Overall progress indicator (current IP / total IPs)
  - Per-IP sub-progress for analysis stages
  - Thread-safe progress updates for parallel processing
  - Console-based progress bars

```python
class ProgressTracker:
    def __init__(self, total_ips: int, parallel: bool = False)
    def update_overall_progress(self, current: int)
    def update_sub_progress(self, ip: IPAddress, stage: str, progress: float)
    def display_progress(self)
```

#### File Output Manager (`FileOutputManager`)
- **Purpose**: Manages file creation and organization for batch results
- **Features**:
  - Output folder creation and validation
  - Filename sanitization for filesystem compatibility
  - File writing with proper error handling
  - Support for JSON and HTML output formats

```python
class FileOutputManager:
    def __init__(self, output_folder: str, format_type: str)
    def create_output_folder(self)
    def generate_filename(self, ip: IPAddress) -> str
    def write_result(self, ip: IPAddress, content: str)
    def validate_output_folder(self) -> bool
```

## Data Models

### Core Data Structures

```python
@dataclass
class AnalysisResult:
    ip_address: IPAddress
    scan_timestamp: datetime
    classifications: List[Classification]
    local_info: Optional[LocalInfoResult]
    internet_info: Optional[InternetInfoResult]
    application_info: Dict[str, ApplicationResult]
    errors: List[AnalysisError]

@dataclass
class Classification:
    name: str
    ip_range: str
    description: str
    qualifies_for: List[str]  # Module names
    rfc_reference: Optional[str]

@dataclass
class LocalInfoResult:
    is_local_subnet: bool
    reachable: bool
    mac_address: Optional[MACAddress]
    nmap_results: NmapResult
    ssl_results: List[SSLResult]
    traceroute_results: List[TracerouteResult]

@dataclass
class InternetInfoResult:
    whois_data: WhoisResult
    geolocation: GeolocationResult
    asn_info: ASNResult
    blocklist_results: List[BlocklistResult]
    reputation_score: Optional[float]

@dataclass
class SSLResult:
    port: int
    protocol: str
    certificate: Optional[Certificate]
    cipher_suites: List[str]
    vulnerabilities: List[str]

@dataclass
class BatchResult:
    total_ips: int
    successful: int
    failed: int
    start_time: datetime
    end_time: datetime
    results: Dict[str, AnalysisResult]
    errors: Dict[str, str]  # IP -> error message
    output_files: List[str]
```

### Database Schema

```sql
-- Core tables for persistent storage
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    ip_version INTEGER NOT NULL,
    scan_timestamp DATETIME NOT NULL,
    scan_duration_ms INTEGER,
    modules_executed TEXT NOT NULL  -- JSON array
);

CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    module_name TEXT NOT NULL,
    result_data TEXT NOT NULL,  -- JSON blob
    success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE TABLE classifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    ip_range TEXT NOT NULL,
    description TEXT,
    qualifies_for TEXT NOT NULL,  -- JSON array
    rfc_reference TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: IP Version Consistency
*For any* valid IP address input, when the application processes the address, all modules should operate in the same IP version mode (IPv4 or IPv6) as determined by the input address format.
**Validates: Requirements 1.4, 1.5**

### Property 2: Output Format Validity
*For any* analysis result and requested output format (JSON, HTML, human-readable), the generated output should be well-formed and valid according to the format specification.
**Validates: Requirements 2.2, 2.3, 2.5**

### Property 3: Database Persistence Completeness
*For any* completed scan, the SQLite database should contain a record with the IP address, scan timestamp, and all collected findings from executed modules.
**Validates: Requirements 3.1, 3.2, 3.5**

### Property 4: Database Location Configuration
*For any* specified database location via command-line option, the database file should be created at that exact location and be accessible for read/write operations.
**Validates: Requirements 3.4**

### Property 5: Dense Mode Filtering
*For any* analysis result in dense reporting mode, the output should contain only test results where information was successfully collected, excluding empty or failed tests.
**Validates: Requirements 4.2**

### Property 6: Full Mode Completeness
*For any* analysis result in full reporting mode, the output should include all executed tests regardless of success or failure, with "no results" displayed for empty tests.
**Validates: Requirements 4.4, 4.5**

### Property 7: Full-Error Mode Detail Inclusion
*For any* analysis result in full-error reporting mode, the output should include all error messages, timeout information, and failure reasons for any failed tests.
**Validates: Requirements 4.7**

### Property 8: Module 4 Access Control
*For any* application execution, Module 4 submodules should only execute when explicitly specified via command-line options, and each submodule should require individual specification.
**Validates: Requirements 5.2, 5.3, 9.7**

### Property 9: Module Availability Validation
*For any* requested module that is not available or properly configured, the application should detect the unavailability before attempting execution and handle it gracefully.
**Validates: Requirements 5.4**

### Property 10: Classification Accuracy
*For any* IP address, the classification module should correctly identify all applicable RFC-defined ranges and custom rules as defined in the classification JSON file.
**Validates: Requirements 6.1, 6.7**

### Property 11: Classification Consistency
*For any* IP address classification, the results should be consistent with the current JSON classification definitions, and the classification should include valid "qualifies for" module specifications.
**Validates: Requirements 6.3, 6.4, 6.5**

### Property 12: Classification CRUD Operations
*For any* add, delete, or modify operation on classification rules via command-line options, the changes should be properly persisted to the JSON file and immediately available for subsequent classifications.
**Validates: Requirements 6.6**

### Property 13: Local Network Analysis Completeness
*For any* IP address processed by the Local Info Module, the module should attempt all configured local analysis methods (subnet check, ping, MAC discovery, nmap scans) and return structured results for each.
**Validates: Requirements 7.1, 7.2, 7.3, 7.8, 7.9, 7.10**

### Property 14: MAC Address Processing
*For any* discovered MAC address, the system should decode the vendor portion and correctly classify whether it represents a network interface or router/gateway based on network topology.
**Validates: Requirements 7.4, 7.5**

### Property 15: Conditional SSL Testing
*For any* discovered web server or mail server port, the Local Info Module should automatically perform SSL analysis using sslyze and include the results in the scan output.
**Validates: Requirements 7.11, 7.12**

### Property 16: SSL Certificate Deduplication
*For any* set of SSL certificates discovered across multiple ports, identical certificates should be reported only once with port-specific differences clearly documented.
**Validates: Requirements 7.13**

### Property 17: Internet Module Qualification
*For any* IP address, the Internet Info Module should execute only when the classification indicates qualification for module 3, unless overridden by force flags.
**Validates: Requirements 8.1**

### Property 18: Internet Information Gathering Completeness
*For any* IP address processed by the Internet Info Module, the module should attempt all configured external lookups (WHOIS, DNS, ASN, geolocation) and return structured results.
**Validates: Requirements 8.3, 8.4, 8.5, 8.6, 8.10**

### Property 19: Reputation Checking Behavior
*For any* IP address, reputation checks (spam lists, DNS blocklists, CrowdSec) should be performed and results should be filtered according to the reporting mode (dense shows only positive findings, full shows all results).
**Validates: Requirements 8.7, 8.8, 8.9, 8.11, 8.12**

### Property 20: Application Integration Error Handling
*For any* application module submodule that encounters authentication or connection errors, the errors should be caught gracefully without terminating the entire analysis process.
**Validates: Requirements 9.8**

### Property 21: Command-Line Interface Validation
*For any* command-line input, the application should validate IP address format before processing and accept valid IPv4 and IPv6 addresses while rejecting invalid formats.
**Validates: Requirements 10.1, 10.3**

### Property 22: Configuration File Processing
*For any* configuration file provided to the application, the settings should be properly loaded and applied as defaults, with command-line options taking precedence over file settings.
**Validates: Requirements 10.7**

### Property 23: Batch Mode Output Format Restriction
*For any* batch mode execution, the application should only proceed when either JSON or HTML output format is specified, rejecting execution with human-readable format.
**Validates: Requirements 11.2, 11.3**

### Property 24: CIDR Expansion Accuracy
*For any* valid CIDR network notation, the batch processor should correctly expand it to the exact set of individual IP addresses within that network range.
**Validates: Requirements 11.4, 11.5**

### Property 25: Batch Size Limit Enforcement
*For any* CIDR network that expands to more than 1024 IP addresses, the application should reject the batch execution with a clear error message before processing begins.
**Validates: Requirements 11.6, 11.7**

### Property 26: Output Folder Management
*For any* specified output folder in batch mode, the application should create the folder if it doesn't exist and successfully write all output files to that location.
**Validates: Requirements 11.8, 11.9, 11.10**

### Property 27: Filename Sanitization
*For any* IP address in batch mode, the generated output filename should be based on the IP address with all characters sanitized for filesystem compatibility across different operating systems.
**Validates: Requirements 11.16**

### Property 28: Progress Indicator Accuracy
*For any* batch processing operation, the overall progress indicator should accurately reflect the current IP number and total count, updating after each IP is processed.
**Validates: Requirements 11.11**

### Property 29: Parallel Processing Thread Safety
*For any* batch mode execution with parallel processing enabled, all progress indicators and file operations should remain thread-safe without data corruption or race conditions.
**Validates: Requirements 11.13, 11.14, 11.15**

## Error Handling

### Error Categories and Strategies

#### 1. Input Validation Errors
- **Invalid IP Address Format**: Immediate rejection with clear error message
- **Invalid Command-Line Arguments**: Help text display and graceful exit
- **Configuration File Errors**: Fallback to defaults with warning messages

#### 2. Network and External Service Errors
- **Network Connectivity Issues**: Timeout handling with configurable retry logic
- **External API Failures**: Graceful degradation with partial results
- **DNS Resolution Failures**: Alternative resolver fallback mechanisms
- **Authentication Failures**: Clear error messages with configuration guidance

#### 3. System Resource Errors
- **Database Access Errors**: Alternative storage mechanisms or read-only mode
- **File System Permissions**: Clear error messages with suggested solutions
- **Memory/CPU Constraints**: Resource usage monitoring and throttling

#### 4. Module-Specific Errors
- **Missing Dependencies**: Clear installation instructions and graceful skipping
- **Tool Execution Failures**: Alternative method fallbacks where possible
- **Data Parsing Errors**: Robust parsing with partial result extraction

### Error Recovery Mechanisms

- **Partial Results**: Continue analysis even if individual modules fail
- **Retry Logic**: Configurable retry attempts for transient failures
- **Fallback Methods**: Alternative approaches when primary methods fail
- **Error Aggregation**: Collect and report all errors at the end of analysis

## Batch Processing Workflow

### Sequential Processing Mode

1. **Input Validation**: Validate CIDR notation and output format requirements
2. **CIDR Expansion**: Expand CIDR to individual IP addresses
3. **Size Validation**: Ensure IP count doesn't exceed 1024 limit
4. **Folder Setup**: Create output folder if it doesn't exist
5. **Sequential Analysis**: Process each IP one at a time
   - Update overall progress indicator
   - Display sub-progress for current IP analysis stages
   - Generate output file for each IP
   - Store results in database
6. **Summary Report**: Display batch completion statistics

### Parallel Processing Mode

1. **Input Validation**: Same as sequential mode
2. **CIDR Expansion**: Same as sequential mode
3. **Size Validation**: Same as sequential mode
4. **Folder Setup**: Same as sequential mode
5. **Thread Pool Creation**: Initialize worker threads based on system resources
6. **Parallel Analysis**: Process multiple IPs concurrently
   - Thread-safe progress tracking
   - Concurrent file writing with locks
   - Independent error handling per IP
   - Database writes with transaction management
7. **Summary Report**: Display batch completion statistics

### Progress Tracking Design

**Overall Progress Indicator**:
```
Processing IP 45/256 [===================>          ] 17.6%
```

**Sub-Progress Indicator** (per IP):
```
  192.168.1.45: Classification [====] Module 2 [===>  ] Module 3 [     ]
```

### Filename Sanitization Rules

- IPv4: Replace dots with underscores (e.g., `192.168.1.1` → `192_168_1_1.json`)
- IPv6: Replace colons with underscores, compress consecutive underscores (e.g., `2001:db8::1` → `2001_db8__1.json`)
- Add appropriate extension based on format (`.json` or `.html`)
- Ensure compatibility with Windows, Linux, and macOS filesystems

## Python Development Framework Integration

This project will follow the standardized Python development framework requirements:

### Virtual Environment Management
- **Isolated Environment**: Each deployment will use a dedicated virtual environment
- **Python Version**: Minimum Python 3.8, with latest 3.x recommended
- **Dependency Isolation**: All packages installed only in project-specific virtual environment

### Project Structure Compliance
```
ip-intelligence-analyzer/
├── src/                    # Source code
│   ├── ip_sentinel/           # Main application package
│   │   ├── __init__.py
│   │   ├── cli.py         # Command-line interface
│   │   ├── analyzer.py    # Main application controller
│   │   ├── modules/       # Analysis modules
│   │   ├── formatters/    # Output formatters
│   │   └── database/      # Database management
├── tests/                 # Test files
│   ├── unit/
│   ├── property/
│   └── integration/
├── docs/                  # Documentation
├── requirements.txt       # Dependencies
├── pyproject.toml        # Project configuration
├── setup.py              # Package setup
└── README.md             # Project documentation
```

### Code Quality Standards
- **PEP 8 Compliance**: All code must conform to PEP 8 standards
- **Automated Formatting**: Use tools like `black` and `isort` for consistent formatting
- **Linting**: Use `flake8` or `pylint` for code quality checks
- **Type Hints**: Use Python type hints for better code documentation and IDE support

### Dependency Management
- **requirements.txt**: Pin exact versions for reproducible builds
- **pyproject.toml**: Modern Python project configuration
- **Lock Files**: Ensure consistent dependency resolution across environments

## Testing Strategy

### Dual Testing Approach

The IP Intelligence Analyzer will employ both unit testing and property-based testing to ensure comprehensive coverage and correctness validation.

#### Unit Testing
Unit tests will focus on:
- **Specific Examples**: Test known IP addresses with expected classification results
- **Edge Cases**: Test boundary conditions like localhost, broadcast addresses, and reserved ranges
- **Error Conditions**: Test invalid inputs, network failures, and malformed responses
- **Integration Points**: Test module interactions and data flow between components
- **Configuration Management**: Test classification rule CRUD operations and file handling

#### Property-Based Testing
Property-based tests will verify universal properties using the **Hypothesis** library for Python:
- **Minimum 100 iterations** per property test to ensure comprehensive input coverage
- **Universal Properties**: Test behaviors that should hold for all valid inputs
- **Input Generation**: Smart generators for IP addresses, network ranges, and configuration data
- **Invariant Validation**: Ensure system invariants are maintained across all operations

#### Property Test Configuration
Each property-based test will:
- Reference its corresponding design document property
- Use the tag format: **Feature: ip-intelligence-analyzer, Property {number}: {property_text}**
- Generate diverse inputs including edge cases automatically
- Validate both positive and negative test cases
- Include performance characteristics where applicable

#### Test Organization
```
tests/
├── unit/
│   ├── test_classification_module.py
│   ├── test_local_info_module.py
│   ├── test_internet_info_module.py
│   ├── test_application_module.py
│   ├── test_output_formatter.py
│   └── test_database_manager.py
├── property/
│   ├── test_ip_version_consistency.py
│   ├── test_output_format_validity.py
│   ├── test_database_persistence.py
│   ├── test_classification_accuracy.py
│   └── test_error_handling.py
├── integration/
│   ├── test_end_to_end_analysis.py
│   ├── test_module_interactions.py
│   └── test_external_service_mocking.py
└── fixtures/
    ├── sample_ips.json
    ├── classification_rules.json
    └── expected_results.json
```

#### Testing Dependencies and Mocking
- **External Services**: Mock external APIs (WHOIS, geolocation, reputation services) for consistent testing
- **Network Operations**: Use test doubles for network scanning and connectivity tests
- **File System**: Temporary directories and files for database and configuration testing
- **Time-Dependent Operations**: Mock datetime for consistent timestamp testing

The testing strategy ensures that both concrete examples work correctly (unit tests) and that universal properties hold across all possible inputs (property-based tests), providing comprehensive validation of the system's correctness.