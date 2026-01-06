"""
Property-based tests for project structure validation.

Feature: ip-intelligence-analyzer, Property 1: Project Structure Compliance
Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
"""

import os
from pathlib import Path

import pytest
from hypothesis import given, strategies as st


class TestProjectStructureCompliance:
    """Property tests for project structure compliance."""

    def test_required_directories_exist(self):
        """
        Property 1: Project Structure Compliance
        For any valid project setup, all required directories should exist.
        **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
        """
        project_root = Path.cwd()
        
        # Required directories according to Python framework standards
        required_dirs = [
            "src",
            "src/ip_mana",
            "src/ip_mana/modules",
            "src/ip_mana/formatters", 
            "src/ip_mana/database",
            "tests",
            "tests/unit",
            "tests/property",
            "tests/integration",
            "docs",
        ]
        
        for dir_path in required_dirs:
            full_path = project_root / dir_path
            assert full_path.exists(), f"Required directory {dir_path} does not exist"
            assert full_path.is_dir(), f"Path {dir_path} exists but is not a directory"

    def test_required_files_exist(self):
        """
        Property 1: Project Structure Compliance  
        For any valid project setup, all required files should exist.
        **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
        """
        project_root = Path.cwd()
        
        # Required files according to Python framework standards
        required_files = [
            "requirements.txt",
            "pyproject.toml", 
            "setup.py",
            "README.md",
            ".gitignore",
            "src/ip_mana/__init__.py",
            "src/ip_mana/cli.py",
            "src/ip_mana/analyzer.py",
            "src/ip_mana/config.py",
            "src/ip_mana/modules/__init__.py",
            "src/ip_mana/formatters/__init__.py",
            "src/ip_mana/database/__init__.py",
            "tests/__init__.py",
        ]
        
        for file_path in required_files:
            full_path = project_root / file_path
            assert full_path.exists(), f"Required file {file_path} does not exist"
            assert full_path.is_file(), f"Path {file_path} exists but is not a file"

    def test_python_package_structure(self):
        """
        Property 1: Project Structure Compliance
        For any Python package directory, it should contain __init__.py files.
        **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
        """
        project_root = Path.cwd()
        
        # All Python package directories should have __init__.py
        package_dirs = [
            "src/ip_mana",
            "src/ip_mana/modules", 
            "src/ip_mana/formatters",
            "src/ip_mana/database",
            "tests",
            "tests/unit",
            "tests/property", 
            "tests/integration",
        ]
        
        for pkg_dir in package_dirs:
            init_file = project_root / pkg_dir / "__init__.py"
            assert init_file.exists(), f"Package {pkg_dir} missing __init__.py"
            assert init_file.is_file(), f"__init__.py in {pkg_dir} is not a file"

    def test_virtual_environment_exists(self):
        """
        Property 1: Project Structure Compliance
        For any valid project setup, a virtual environment should exist.
        **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
        """
        project_root = Path.cwd()
        venv_path = project_root / "venv"
        
        assert venv_path.exists(), "Virtual environment directory does not exist"
        assert venv_path.is_dir(), "venv path exists but is not a directory"
        
        # Check for key venv files/directories
        venv_indicators = [
            "pyvenv.cfg",
            "bin" if os.name != "nt" else "Scripts",
            "lib",
        ]
        
        for indicator in venv_indicators:
            indicator_path = venv_path / indicator
            assert indicator_path.exists(), f"Virtual environment missing {indicator}"

    def test_configuration_files_valid(self):
        """
        Property 1: Project Structure Compliance
        For any valid project setup, configuration files should be properly formatted.
        **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
        """
        project_root = Path.cwd()
        
        # Check pyproject.toml exists and is readable
        pyproject_path = project_root / "pyproject.toml"
        assert pyproject_path.exists(), "pyproject.toml does not exist"
        
        # Check requirements.txt exists and is readable
        requirements_path = project_root / "requirements.txt"
        assert requirements_path.exists(), "requirements.txt does not exist"
        
        # Verify files are readable
        try:
            with open(pyproject_path, "r") as f:
                content = f.read()
                assert len(content) > 0, "pyproject.toml is empty"
                assert "[project]" in content, "pyproject.toml missing [project] section"
        except Exception as e:
            pytest.fail(f"Failed to read pyproject.toml: {e}")
            
        try:
            with open(requirements_path, "r") as f:
                content = f.read()
                assert len(content) > 0, "requirements.txt is empty"
        except Exception as e:
            pytest.fail(f"Failed to read requirements.txt: {e}")

    @given(st.sampled_from([
        "src/ip_mana/modules",
        "src/ip_mana/formatters", 
        "src/ip_mana/database"
    ]))
    def test_module_directories_structure(self, module_dir):
        """
        Property 1: Project Structure Compliance
        For any module directory, it should follow proper Python package structure.
        **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
        """
        project_root = Path.cwd()
        module_path = project_root / module_dir
        
        # Module directory should exist
        assert module_path.exists(), f"Module directory {module_dir} does not exist"
        assert module_path.is_dir(), f"Module path {module_dir} is not a directory"
        
        # Should have __init__.py
        init_file = module_path / "__init__.py"
        assert init_file.exists(), f"Module {module_dir} missing __init__.py"
        
        # Should contain at least one Python file besides __init__.py
        python_files = list(module_path.glob("*.py"))
        assert len(python_files) >= 1, f"Module {module_dir} has no Python files"