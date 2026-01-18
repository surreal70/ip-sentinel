# IP-ManA Configuration Guide

This document describes all configuration options for IP Intelligence Analyzer.

## Table of Contents

1. [Classification Configuration](#classification-configuration)
2. [Application Credentials](#application-credentials)
3. [Database Configuration](#database-configuration)
4. [Command-Line Options](#command-line-options)
5. [Environment Variables](#environment-variables)

## Classification Configuration

### Default Classifications File

On first run, IP-ManA creates `classifications.json` with RFC-compliant IP ranges:

```json
{
  "Private Networks (RFC 1918)": {
    "ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "description": "Private IPv4 address space",
    "qualifies_for": ["module2"],
    "rfc_reference": "RFC 1918"
  },
  "Localhost": {
    "ranges": ["127.0.0.0/8", "::1/128"],
    "description": "Loopback addresses",
    "qualifies_for": ["module2"],
    "rfc_reference": "RFC 1122, RFC 4291"
  },
  "Link-Local": {
    "ranges": ["169.254.0.0/16", "fe80::/10"],
    "description": "Link-local addresses",
    "qualifies_for": ["module2"],
    "rfc_reference": "RFC 3927, RFC 4291"
  },
  "Multicast": {
    "ranges": ["224.0.0.0/4", "ff00::/8"],
    "description": "Multicast addresses",
    "qualifies_for": [],
    "rfc_reference": "RFC 5771, RFC 4291"
  },
  "Public Internet": {
    "ranges": ["0.0.0.0/0"],
    "description": "Public IPv4 addresses",
    "qualifies_for": ["module2", "module3"],
    "rfc_reference": null
  }
}
```

### Classification Fields

- **ranges**: List of CIDR notation IP ranges
- **description**: Human-readable description
- **qualifies_for**: Which modules should run for this classification
  - `module2`: Local Information Module
  - `module3`: Internet Information Module
  - `module4`: Application Module (requires explicit activation)
- **rfc_reference**: RFC document reference (optional)

### Managing Classifications via CLI

**Add a classification**:
```bash
ip-mana --add-classification \
    "DMZ Network" \
    "172.16.100.0/24" \
    "Demilitarized zone for public services" \
    "module2,module3"
```

**Delete a classification**:
```bash
ip-mana --delete-classification "DMZ Network"
```

**List all classifications**:
```bash
ip-mana --list-classifications
```

### Manual Configuration File Editing

You can also edit `classifications.json` directly:

```json
{
  "Custom Office Network": {
    "ranges": ["10.50.0.0/16", "10.51.0.0/16"],
    "description": "Corporate office networks",
    "qualifies_for": ["module2", "module3", "module4"],
    "rfc_reference": null
  }
}
```

**Important**: Restart IP-ManA after manual edits to reload configuration.

## Application Credentials

### Credentials File Location

Default: `config/app_credentials.json`

Custom location:
```bash
ip-mana --credentials /path/to/custom-credentials.json --netbox 192.168.1.1
```

### Credentials File Format

```json
{
  "netbox": {
    "enabled": true,
    "url": "https://netbox.example.com",
    "token": "your-api-token-here",
    "verify_ssl": false,
    "timeout": 30
  },
  "checkmk": {
    "enabled": true,
    "url": "https://checkmk.example.com/site/api",
    "username": "automation",
    "password": "your-password-here",
    "verify_ssl": false,
    "timeout": 30
  },
  "openvas": {
    "enabled": true,
    "url": "https://openvas.example.com",
    "username": "admin",
    "password": "your-password-here",
    "verify_ssl": false,
    "timeout": 60
  },
  "openitcockpit": {
    "enabled": false,
    "url": "https://openitcockpit.example.com",
    "api_key": "your-api-key-here",
    "verify_ssl": true,
    "timeout": 30
  },
  "infoblox": {
    "enabled": false,
    "url": "https://infoblox.example.com",
    "username": "admin",
    "password": "your-password-here",
    "verify_ssl": true,
    "timeout": 30
  }
}
```

### Credential Fields

- **enabled**: Whether this submodule is available (true/false)
- **url**: Base URL for the application API
- **token/api_key**: API token (for token-based auth)
- **username/password**: Credentials (for basic auth)
- **verify_ssl**: Whether to verify SSL certificates (true/false)
- **timeout**: Request timeout in seconds

### Security Best Practices

1. **Never commit credentials**: Ensure `config/app_credentials.json` is in `.gitignore`
2. **Use environment variables**: For sensitive deployments
3. **Restrict file permissions**:
   ```bash
   chmod 600 config/app_credentials.json
   ```
4. **Use separate credentials**: Don't reuse production credentials for testing
5. **Enable SSL verification**: Set `verify_ssl: true` in production
6. **Rotate credentials**: Regularly update API tokens and passwords

### Example Configurations

**NetBox with API Token**:
```json
{
  "netbox": {
    "enabled": true,
    "url": "https://netbox.company.com",
    "token": "a1b2c3d4e5f6g7h8i9j0",
    "verify_ssl": true,
    "timeout": 30
  }
}
```

**CheckMK with Basic Auth**:
```json
{
  "checkmk": {
    "enabled": true,
    "url": "https://monitoring.company.com/prod/check_mk/api/1.0",
    "username": "automation",
    "password": "SecurePassword123!",
    "verify_ssl": true,
    "timeout": 30
  }
}
```

**OpenVAS with Custom Timeout**:
```json
{
  "openvas": {
    "enabled": true,
    "url": "https://scanner.company.com:9392",
    "username": "admin",
    "password": "VerySecurePassword!",
    "verify_ssl": false,
    "timeout": 120
  }
}
```

## Database Configuration

### Default Database Location

Default: `ip_analysis.db` in current working directory

### Custom Database Location

**Via command-line**:
```bash
ip-mana --database /var/lib/ip-mana/production.db 192.168.1.1
```

**Via environment variable** (planned):
```bash
export IP_MANA_DATABASE=/var/lib/ip-mana/production.db
ip-mana 192.168.1.1
```

### Disable Database Storage

```bash
ip-mana --no-database 192.168.1.1
```

### Database Schema

The SQLite database contains:

**scans table**:
- `id`: Primary key
- `ip_address`: IP address analyzed
- `ip_version`: 4 or 6
- `scan_timestamp`: When scan was performed
- `scan_duration_ms`: How long scan took
- `modules_executed`: JSON array of modules run

**scan_results table**:
- `id`: Primary key
- `scan_id`: Foreign key to scans table
- `module_name`: Name of module
- `result_data`: JSON blob with results
- `success`: Boolean success flag
- `error_message`: Error message if failed

**classifications table**:
- `id`: Primary key
- `name`: Classification name
- `ip_range`: CIDR notation
- `description`: Description
- `qualifies_for`: JSON array of modules
- `rfc_reference`: RFC reference
- `created_at`: Creation timestamp

### Database Maintenance

**Backup database**:
```bash
cp ip_analysis.db ip_analysis.db.backup
```

**Query database**:
```bash
sqlite3 ip_analysis.db "SELECT * FROM scans ORDER BY scan_timestamp DESC LIMIT 10;"
```

**Clean old scans**:
```bash
sqlite3 ip_analysis.db "DELETE FROM scans WHERE scan_timestamp < datetime('now', '-30 days');"
```

**Vacuum database**:
```bash
sqlite3 ip_analysis.db "VACUUM;"
```

## Command-Line Options

### Complete Options Reference

```
Usage: ip-mana [OPTIONS] IP_ADDRESS

Options:
  --version                Show version and exit
  --help                   Show help message and exit
  
  Output Format:
  --json                   Output in JSON format
  --html                   Output in HTML format
  (default: human-readable console output)
  
  Reporting Mode:
  --dense                  Show only collected data (default)
  --full                   Show all tests including empty results
  --full-err               Include error messages and timeouts
  
  Module Control:
  --force-internet         Force Module 3 even for private IPs
  --force-module3          Alias for --force-internet
  
  Module 4 (Application Integration):
  --netbox                 Query NetBox IPAM
  --checkmk                Query CheckMK monitoring
  --openvas                Query OpenVAS scanner
  --openitcockpit          Query OpenITCockpit (planned)
  --infoblox               Query Infoblox (planned)
  --credentials PATH       Custom credentials file
  
  Database:
  --database PATH          Custom database location
  --no-database            Disable database storage
  
  Classification Management:
  --list-classifications   List all classifications
  --add-classification NAME RANGE DESC MODULES
                          Add custom classification
  --delete-classification NAME
                          Delete classification
  
  Debugging:
  --verbose                Enable verbose output
  --debug                  Enable debug mode (planned)
```

### Option Examples

**Multiple options combined**:
```bash
ip-mana --json --full --netbox --checkmk --database /tmp/test.db 192.168.1.1
```

**Long-form options**:
```bash
ip-mana --output-format=json --reporting-mode=full 192.168.1.1
```

## Environment Variables

### Planned Environment Variables

These are planned for future releases:

```bash
# Database location
export IP_MANA_DATABASE=/var/lib/ip-mana/production.db

# Credentials file
export IP_MANA_CREDENTIALS=/etc/ip-mana/credentials.json

# Default output format
export IP_MANA_OUTPUT_FORMAT=json

# Default reporting mode
export IP_MANA_REPORTING_MODE=full

# Enable verbose by default
export IP_MANA_VERBOSE=1

# Classification file location
export IP_MANA_CLASSIFICATIONS=/etc/ip-mana/classifications.json
```

## Configuration File (Future)

### Planned Configuration File Support

Future versions will support a configuration file (e.g., `~/.ip-mana/config.yaml`):

```yaml
# IP-ManA Configuration File

# Default output format: human, json, html
output_format: human

# Default reporting mode: dense, full, full-err
reporting_mode: dense

# Database configuration
database:
  enabled: true
  path: /var/lib/ip-mana/production.db
  auto_cleanup: true
  retention_days: 90

# Module configuration
modules:
  module1:
    enabled: true
  module2:
    enabled: true
    nmap_options: "-T4 -F"
  module3:
    enabled: true
    force_for_private: false
  module4:
    enabled: false
    credentials_file: /etc/ip-mana/credentials.json

# Logging
logging:
  level: INFO
  file: /var/log/ip-mana/ip-mana.log
  max_size_mb: 100
  backup_count: 5

# Performance
performance:
  timeout_seconds: 300
  max_concurrent_modules: 4
  rate_limit_delay: 1.0
```

## Advanced Configuration

### Custom Module Configuration

For advanced users, module behavior can be customized by editing source code:

**Module 2 (Local Info)** - `src/ip_mana/modules/local_info.py`:
- Nmap scan options
- Timeout values
- Port ranges

**Module 3 (Internet Info)** - `src/ip_mana/modules/internet_info.py`:
- API endpoints
- Timeout values
- Retry logic

### Integration with Configuration Management

**Ansible example**:
```yaml
- name: Deploy IP-ManA configuration
  template:
    src: app_credentials.json.j2
    dest: /etc/ip-mana/app_credentials.json
    mode: 0600
    owner: ipmana
    group: ipmana
```

**Puppet example**:
```puppet
file { '/etc/ip-mana/app_credentials.json':
  ensure  => file,
  content => template('ipmana/app_credentials.json.erb'),
  mode    => '0600',
  owner   => 'ipmana',
  group   => 'ipmana',
}
```

## Troubleshooting Configuration

### Verify Configuration

```bash
# Check if classifications file exists
ls -la classifications.json

# Validate JSON syntax
python -m json.tool classifications.json

# Check credentials file
python -m json.tool config/app_credentials.json

# Test database connection
sqlite3 ip_analysis.db "SELECT 1;"
```

### Common Configuration Errors

**Error**: `FileNotFoundError: config/app_credentials.json`
**Solution**: Copy from example: `cp config/app_credentials.example.json config/app_credentials.json`

**Error**: `JSONDecodeError: Expecting property name`
**Solution**: Validate JSON syntax with `python -m json.tool file.json`

**Error**: `PermissionError: [Errno 13] Permission denied`
**Solution**: Check file permissions: `chmod 600 config/app_credentials.json`

**Error**: `sqlite3.OperationalError: unable to open database file`
**Solution**: Ensure directory exists and is writable

## Best Practices

1. **Version control**: Keep example configurations in git, not actual credentials
2. **Documentation**: Document custom classifications and their purposes
3. **Testing**: Test configuration changes in non-production environment first
4. **Backup**: Regularly backup database and configuration files
5. **Security**: Use restrictive file permissions for sensitive files
6. **Monitoring**: Monitor database size and performance
7. **Updates**: Review configuration when upgrading IP-ManA versions

## Additional Resources

- Main documentation: [README.md](../README.md)
- Usage examples: [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)
- License information: [LICENSE](../LICENSE)

---

For questions about configuration, open an issue on GitHub or consult the documentation.
