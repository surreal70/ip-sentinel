# Technology Stack

## Development Environment

- **Primary Languages**: Python 3.8+, Unix Shell (Bash/POSIX), PowerShell 5.1+/PowerShell Core 7+
- **Editor**: VS Code with Kiro AI assistant integration
- **Version Control**: Git

## Python Framework Stack

- **Python Versions**: 3.8 minimum, latest 3.x recommended
- **Virtual Environments**: Project-isolated environments (venv/virtualenv)
- **Dependency Management**: requirements.txt or pyproject.toml
- **Code Standards**: PEP 8 compliance enforced
- **Linting**: PEP 8 compliant tools

## Shell Scripting Standards

- **Shell Types**: Bash with POSIX compatibility fallback
- **Error Handling**: `set -euo pipefail` standard
- **Portability**: Cross-Unix system compatibility
- **Documentation**: Inline comments and function documentation required

## PowerShell Standards

- **PowerShell Versions**: 5.1 minimum, PowerShell Core 7+ recommended
- **Naming Conventions**: Verb-Noun cmdlet naming with approved verbs
- **Error Handling**: Try-Catch-Finally blocks with structured error handling
- **Documentation**: Comment-based help with Get-Help support
- **Code Analysis**: PSScriptAnalyzer compliance enforced
- **Module Structure**: Standardized module manifests and organization

## Project Structure Standards

```
project/
├── src/           # Source code
├── tests/         # Test files
├── docs/          # Documentation
├── requirements.txt or pyproject.toml
└── README.md
```

## Common Commands

### Python Projects
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Code formatting check
flake8 src/
```

### Shell Scripts
```bash
# Validate shell script
shellcheck script.sh

# Test script portability
bash -n script.sh
```

### PowerShell Scripts
```powershell
# Analyze PowerShell code
Invoke-ScriptAnalyzer -Path script.ps1

# Test PowerShell syntax
Get-Command -Syntax Test-Path

# Run Pester tests
Invoke-Pester
```