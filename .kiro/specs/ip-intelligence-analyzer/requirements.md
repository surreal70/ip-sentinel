# Requirements Document

## Introduction

IP-ManA is a Python console application that gathers comprehensive intelligence about IP addresses through multiple analysis modules. The system provides flexible output formats, persistent storage, and modular architecture for both local and internet-based information gathering.

## Glossary

- **IP-Man**: IP Management and Analysis application
- **Classification_Module**: Module that categorizes IP addresses based on RFC-defined ranges
- **Local_Info_Module**: Module that gathers information from the local network environment
- **Internet_Info_Module**: Module that queries external services for IP intelligence
- **Application_Module**: Module that interfaces with enterprise applications for IP data
- **SQLite_Database**: Local database storing scan results and metadata
- **Output_Formatter**: Component responsible for generating human-readable, JSON, or HTML output
- **Special_IP_Range**: IP address ranges defined by RFCs (private, multicast, localhost, etc.)
- **Dense_Mode**: Reporting mode showing only collected data
- **Full_Mode**: Reporting mode showing all tests including empty results
- **Full_Error_Mode**: Reporting mode including error details and timeout information
- **Batch_Mode**: Processing mode for analyzing multiple IP addresses from CIDR networks
- **Batch_Processor**: Component that manages batch analysis of multiple IP addresses
- **CIDR_Notation**: Classless Inter-Domain Routing notation for specifying IP network ranges
- **Progress_Tracker**: Component that displays real-time progress for batch operations
- **Parallel_Processing**: Concurrent processing of multiple IP addresses using multiple threads

## Requirements

### Requirement 1: Application Architecture and Licensing

**User Story:** Als Entwickler möchte ich eine MIT-lizenzierte Python-Konsolenanwendung, damit ich IP-Adressen analysieren kann.

#### Acceptance Criteria

1. THE Application SHALL be implemented as a Python console application
2. THE Application SHALL use MIT license for all source code
3. THE Application SHALL support both IPv4 and IPv6 address formats
4. WHEN an IPv4 address is provided, THE Application SHALL process all modules in IPv4 mode
5. WHEN an IPv6 address is provided, THE Application SHALL process all modules in IPv6 mode

### Requirement 2: Output Format Management

**User Story:** Als Benutzer möchte ich verschiedene Ausgabeformate wählen können, damit ich die Ergebnisse in der gewünschten Form erhalte.

#### Acceptance Criteria

1. THE Output_Formatter SHALL support human-readable console output as default format
2. THE Output_Formatter SHALL support JSON output format via command-line switch
3. THE Output_Formatter SHALL support HTML output format via command-line switch
4. WHEN no output format is specified, THE Application SHALL use human-readable console output
5. THE Output_Formatter SHALL generate well-formed output in the requested format

### Requirement 3: Data Persistence and Storage

**User Story:** Als Benutzer möchte ich Scan-Ergebnisse persistent speichern, damit ich historische Daten analysieren kann.

#### Acceptance Criteria

1. THE Application SHALL store scan results in a SQLite database
2. THE SQLite_Database SHALL include IP address, scan datetime, and all test findings
3. THE SQLite_Database SHALL be created in the same directory as the invoking script by default
4. THE Application SHALL provide command-line option to specify alternative database location
5. WHEN storing scan results, THE Application SHALL include timestamp of system invoking the test

### Requirement 4: Reporting Modes

**User Story:** Als Benutzer möchte ich verschiedene Berichtsmodi wählen können, damit ich die Detailtiefe der Ausgabe steuern kann.

#### Acceptance Criteria

1. THE Application SHALL support "dense" reporting mode as default
2. WHEN in dense mode, THE Application SHALL show only data where information has been collected
3. THE Application SHALL support "full" reporting mode via command-line option
4. WHEN in full mode, THE Application SHALL show all tests including those with no results
5. WHEN a test has no results in full mode, THE Application SHALL display "no results"
6. THE Application SHALL support "full-err" reporting mode via command-line option
7. WHEN in full-err mode, THE Application SHALL include error messages, timeouts, and failure reasons

### Requirement 5: Module Execution Control

**User Story:** Als Benutzer möchte ich steuern können, welche Module ausgeführt werden, damit ich gezielt bestimmte Analysen durchführen kann.

#### Acceptance Criteria

1. THE Application SHALL execute Module 1, Module 2, and Module 3 by default
2. THE Application SHALL require explicit command-line options to invoke Module 4 submodules
3. WHEN Module 4 is requested, THE Application SHALL require each submodule to be explicitly specified
4. THE Application SHALL validate module availability before execution
5. THE Application SHALL provide clear feedback when requested modules are unavailable

### Requirement 6: IP Classification Module (Module 1)

**User Story:** Als Benutzer möchte ich IP-Adressen nach RFC-Standards klassifizieren, damit ich deren Eigenschaften verstehe.

#### Acceptance Criteria

1. THE Classification_Module SHALL identify special IP ranges defined in RFCs
2. WHEN first run, THE Classification_Module SHALL create a JSON file containing all special IP range definitions
3. THE Classification_Module SHALL check existing JSON definitions on subsequent runs
4. THE Classification_Module SHALL classify IP addresses according to JSON file contents
5. THE Classification_Module SHALL include "qualifies for" field specifying which test modules to run
6. THE Application SHALL provide command-line options to add, delete, and modify classifications manually
7. THE Classification_Module SHALL support private networks, multicast, localhost, and other RFC-defined ranges

### Requirement 7: Local Information Gathering Module (Module 2)

**User Story:** Als Benutzer möchte ich lokale Netzwerkinformationen über IP-Adressen sammeln, damit ich deren lokale Eigenschaften verstehe.

#### Acceptance Criteria

1. THE Local_Info_Module SHALL determine if IP address is part of local machine's subnet
2. THE Local_Info_Module SHALL test IP address reachability via ping
3. THE Local_Info_Module SHALL discover associated MAC address when available
4. THE Local_Info_Module SHALL decode vendor part of MAC address
5. THE Local_Info_Module SHALL evaluate if MAC address belongs to network interface or router/gateway
6. THE Local_Info_Module SHALL generate traceroute using multiple methods (traceroute, ping packets, HTTP packets)
7. THE Local_Info_Module SHALL perform reverse DNS lookup against local resolver
8. THE Local_Info_Module SHALL execute nmap discovery scan
9. THE Local_Info_Module SHALL execute nmap OS discovery scan
10. THE Local_Info_Module SHALL execute nmap port scan for standard TCP and UDP ports
11. WHEN webserver port is discovered, THE Local_Info_Module SHALL run SSL test using sslyze
12. WHEN mailserver port is discovered, THE Local_Info_Module SHALL run SSL test using sslyze
13. WHEN identical certificates are found, THE Local_Info_Module SHALL report once and describe differences by port

### Requirement 8: Internet Information Gathering Module (Module 3)

**User Story:** Als Benutzer möchte ich Internet-basierte Informationen über IP-Adressen sammeln, damit ich deren öffentliche Eigenschaften verstehe.

#### Acceptance Criteria

1. THE Internet_Info_Module SHALL execute only when classification indicates module 3 qualification
2. THE Application SHALL provide --force-internet or --force-module3 switch to override classification restrictions
3. THE Internet_Info_Module SHALL perform whois lookup and gather available information
4. THE Internet_Info_Module SHALL perform reverse DNS lookup against internet resolvers (Cloudflare, Google)
5. THE Internet_Info_Module SHALL perform reverse lookup using Hackertarget service API
6. THE Internet_Info_Module SHALL determine ASN (Autonomous System Number) ownership
7. THE Internet_Info_Module SHALL check IP address against spam lists
8. THE Internet_Info_Module SHALL check IP address against DNS blocklists
9. THE Internet_Info_Module SHALL check IP address against CrowdSec database
10. THE Internet_Info_Module SHALL gather geolocation data for IP address
11. WHEN in dense mode, THE Internet_Info_Module SHALL show only positive findings for blocklist checks
12. WHEN in full mode, THE Internet_Info_Module SHALL show all blocklist check results

### Requirement 9: Application-Based Information Gathering Module (Module 4)

**User Story:** Als Benutzer möchte ich Informationen aus Enterprise-Anwendungen über IP-Adressen sammeln, damit ich interne Systemdaten nutzen kann.

#### Acceptance Criteria

1. THE Application_Module SHALL provide NetBox submodule for IPAM system queries
2. THE NetBox_Submodule SHALL query information via NetBox API
3. THE Application_Module SHALL provide CheckMK submodule for monitoring system queries
4. THE Application_Module SHALL provide OpenITCockpit submodule for IT management queries
5. THE Application_Module SHALL provide OpenVAS submodule for vulnerability assessment queries
6. THE Application_Module SHALL provide Infoblox submodule for DNS/DHCP system queries
7. WHEN Module 4 is invoked, THE Application SHALL require explicit specification of each submodule
8. THE Application_Module SHALL handle authentication and connection errors gracefully

### Requirement 10: Command-Line Interface

**User Story:** Als Benutzer möchte ich eine umfassende Kommandozeilen-Schnittstelle, damit ich alle Funktionen effizient nutzen kann.

#### Acceptance Criteria

1. THE Application SHALL accept IP address as primary command-line argument
2. THE Application SHALL provide help documentation via --help option
3. THE Application SHALL validate IP address format before processing
4. THE Application SHALL provide clear error messages for invalid inputs
5. THE Application SHALL support verbose output mode for debugging
6. THE Application SHALL provide version information via --version option
7. THE Application SHALL support configuration file for default settings

### Requirement 11: Batch Processing Mode

**User Story:** Als Benutzer möchte ich mehrere IP-Adressen in einem Batch-Modus verarbeiten, damit ich große Netzwerke effizient analysieren kann.

#### Acceptance Criteria

1. THE Application SHALL provide --batch command-line option to enable batch processing mode
2. WHEN batch mode is enabled, THE Application SHALL require either --json or --html output format
3. WHEN batch mode is enabled without --json or --html, THE Application SHALL reject execution with clear error message
4. THE Application SHALL accept CIDR network notation as input in batch mode
5. WHEN CIDR notation is provided, THE Application SHALL expand it to individual IP addresses
6. THE Application SHALL enforce maximum limit of 1024 IP addresses per batch run
7. WHEN CIDR expansion exceeds 1024 addresses, THE Application SHALL reject execution with clear error message
8. THE Application SHALL require --output-folder parameter in batch mode
9. WHEN --output-folder is specified, THE Application SHALL create the folder if it does not exist
10. THE Application SHALL generate separate output files for each IP address in the specified folder
11. THE Application SHALL display overall progress indicator showing current IP address number and total count
12. THE Application SHALL display sub-progress indicator for individual IP address processing stages
13. THE Application SHALL provide --parallel option to enable parallel processing of IP addresses
14. WHEN --parallel is enabled, THE Application SHALL process multiple IP addresses concurrently
15. WHEN --parallel is enabled, THE Application SHALL maintain thread-safe progress indicators
16. THE Application SHALL generate output filenames based on IP address (sanitized for filesystem compatibility)