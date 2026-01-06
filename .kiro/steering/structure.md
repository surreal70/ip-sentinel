# Project Structure

## Repository Organization

This repository follows a specification-driven development approach with clear separation of concerns:

```
.kiro/
├── specs/                          # Feature specifications
│   ├── python-development-framework/
│   │   └── requirements.md         # Python framework requirements
│   ├── unix-shell-scripting-framework/
│   │   └── requirements.md         # Shell scripting requirements
│   └── powershell-development-framework/
│       └── requirements.md         # PowerShell framework requirements
└── steering/                       # AI assistant guidance
    ├── product.md                  # Product overview
    ├── tech.md                     # Technology stack
    └── structure.md                # This file
```

## Specification Structure

Each framework specification includes:
- **requirements.md**: Detailed user stories and acceptance criteria in German
- Clear glossary of domain-specific terms
- Structured acceptance criteria using WHEN/THEN/SHALL format

## Development Conventions

### Language Detection
- Frameworks must validate project type before initialization
- Warn when non-target language files are detected
- Require explicit confirmation for mixed-language projects

### Framework Isolation
- Python framework: Only for Python projects (.py files)
- Shell framework: Only for shell script projects (.sh, .bash files)
- PowerShell framework: Only for PowerShell projects (.ps1, .psm1, .psd1 files)
- Each framework validates its target environment

### Documentation Standards
- All requirements written in German
- User stories follow standard format: "Als [Rolle] möchte ich [Ziel], damit [Nutzen]"
- Acceptance criteria use structured WHEN/THEN/SHALL format
- Technical terms defined in glossary section

## File Naming Conventions
- Specification files: `requirements.md`
- Steering files: descriptive names (product.md, tech.md, structure.md)
- Use lowercase with hyphens for directory names