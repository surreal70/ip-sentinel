# IP Intelligence Analyzer (IP-ManA)

A comprehensive Python console application for IP address intelligence gathering through multiple analysis modules.

## Features

- **Modular Architecture**: Four specialized analysis modules for comprehensive IP intelligence
- **Multiple Output Formats**: Human-readable, JSON, and HTML output options
- **Flexible Reporting**: Dense, full, and full-error reporting modes
- **Persistent Storage**: SQLite database for historical analysis data
- **Enterprise Integration**: Plugin architecture for enterprise application integration

## Requirements

- Python 3.8 or higher
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ip-intelligence-analyzer
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install the package in development mode:
```bash
pip install -e .
```

## Usage

Basic IP analysis:
```bash
ip-mana 192.168.1.1
```

JSON output format:
```bash
ip-mana --json 192.168.1.1
```

Full reporting mode:
```bash
ip-mana --full 192.168.1.1
```

For complete usage information:
```bash
ip-mana --help
```

## Development

### Code Quality

This project follows PEP 8 standards and uses automated code formatting:

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
flake8 src/ tests/
```

### Testing

Run the test suite:
```bash
pytest
```

Run property-based tests:
```bash
pytest tests/property/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Architecture

The application consists of four main analysis modules:

1. **Classification Module**: Categorizes IP addresses based on RFC standards
2. **Local Information Module**: Gathers network information from local environment
3. **Internet Information Module**: Queries external services for public IP data
4. **Application Module**: Interfaces with enterprise applications

## Contributing

1. Ensure Python 3.8+ is installed
2. Set up virtual environment and install dependencies
3. Follow PEP 8 coding standards
4. Write tests for new functionality
5. Run the full test suite before submitting changes