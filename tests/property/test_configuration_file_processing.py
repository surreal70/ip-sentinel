"""
Property-based tests for configuration file processing.

Feature: ip-intelligence-analyzer, Property 22: Configuration File Processing
Validates: Requirements 10.7
"""

import pytest
from hypothesis import given, strategies as st, settings
from pathlib import Path
import tempfile
import json

from src.ip_sentinel.config import Config, ConfigManager
from src.ip_sentinel.cli import build_config_from_args
import argparse


# Strategy for generating configuration data
@st.composite
def config_data_strategy(draw):
    """Generate valid configuration data."""
    return {
        "database_path": draw(st.one_of(
            st.none(),
            st.text(min_size=1, max_size=50).map(lambda x: f"/tmp/{x}.db")
        )),
        "output_format": draw(st.sampled_from(["human", "json", "html"])),
        "reporting_mode": draw(st.sampled_from(["dense", "full", "full-err"])),
        "force_internet": draw(st.booleans()),
        "verbose": draw(st.booleans()),
        "enabled_modules": {
            "classification": draw(st.booleans()),
            "local_info": draw(st.booleans()),
            "internet_info": draw(st.booleans()),
            "netbox": draw(st.booleans()),
            "checkmk": draw(st.booleans()),
            "openitcockpit": draw(st.booleans()),
            "openvas": draw(st.booleans()),
            "infoblox": draw(st.booleans()),
        }
    }


@settings(max_examples=100, deadline=None)
@given(config_data=config_data_strategy())
def test_configuration_file_processing_property(config_data):
    """
    Property 22: Configuration File Processing

    For any configuration file provided to the application, the settings should be
    properly loaded and applied as defaults, with command-line options taking
    precedence over file settings.

    Validates: Requirements 10.7
    """
    # Create a temporary configuration file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        config_file = f.name

    try:
        # Load configuration from file
        config_manager = ConfigManager(config_path=Path(config_file))
        loaded_config = config_manager.load_config()

        # Property 1: All settings from file should be loaded
        assert loaded_config.output_format == config_data["output_format"], \
            "Output format should be loaded from config file"
        assert loaded_config.reporting_mode == config_data["reporting_mode"], \
            "Reporting mode should be loaded from config file"
        assert loaded_config.force_internet == config_data["force_internet"], \
            "Force internet flag should be loaded from config file"
        assert loaded_config.verbose == config_data["verbose"], \
            "Verbose flag should be loaded from config file"

        # Property 2: Database path should be converted to Path object
        if config_data["database_path"]:
            assert loaded_config.database_path == Path(config_data["database_path"]), \
                "Database path should be converted to Path object"
        else:
            assert loaded_config.database_path is None, \
                "None database path should remain None"

        # Property 3: Enabled modules should be loaded correctly
        for module, enabled in config_data["enabled_modules"].items():
            assert loaded_config.enabled_modules[module] == enabled, \
                f"Module {module} enabled status should match config file"

        # Property 4: Configuration should be saveable and reloadable
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f2:
            save_file = f2.name

        try:
            config_manager2 = ConfigManager(config_path=Path(save_file))
            config_manager2.save_config(loaded_config)

            # Reload and verify
            reloaded_config = config_manager2.load_config()

            assert reloaded_config.output_format == loaded_config.output_format, \
                "Reloaded config should match original"
            assert reloaded_config.reporting_mode == loaded_config.reporting_mode, \
                "Reloaded config should match original"
            assert reloaded_config.force_internet == loaded_config.force_internet, \
                "Reloaded config should match original"

        finally:
            Path(save_file).unlink(missing_ok=True)

    finally:
        # Clean up
        Path(config_file).unlink(missing_ok=True)


@settings(max_examples=100, deadline=None)
@given(
    output_format=st.sampled_from(["human", "json", "html"]),
    reporting_mode=st.sampled_from(["dense", "full", "full-err"]),
    force_internet=st.booleans(),
    verbose=st.booleans()
)
def test_cli_args_override_config_file(
        output_format,
        reporting_mode,
        force_internet,
        verbose):
    """
    Property: Command-line arguments should take precedence over config file settings.

    For any configuration file and command-line arguments, the command-line arguments
    should override the file settings.

    Validates: Requirements 10.7
    """
    # Create a config file with different settings
    file_config = {
        "output_format": "human",
        "reporting_mode": "dense",
        "force_internet": False,
        "verbose": False
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(file_config, f)
        config_file = f.name

    try:
        # Create mock command-line arguments
        args = argparse.Namespace(
            json=(output_format == "json"),
            html=(output_format == "html"),
            full=(reporting_mode == "full"),
            full_err=(reporting_mode == "full-err"),
            force_internet=force_internet,
            force_module3=False,
            verbose=verbose,
            db_path=None,
            netbox=False,
            checkmk=False,
            openitcockpit=False,
            openvas=False,
            infoblox=False
        )

        # Build config from args (which should override file settings)
        config = build_config_from_args(args)

        # Property: CLI args should override file settings
        assert config.output_format == output_format, \
            "CLI output format should override file setting"
        assert config.reporting_mode == reporting_mode, \
            "CLI reporting mode should override file setting"
        assert config.force_internet == force_internet, \
            "CLI force_internet should override file setting"
        assert config.verbose == verbose, \
            "CLI verbose should override file setting"

    finally:
        Path(config_file).unlink(missing_ok=True)


def test_config_file_not_found_uses_defaults():
    """Test that missing config file results in default configuration."""
    # Use a non-existent config file path
    non_existent_path = Path("/tmp/nonexistent_config_12345.json")

    config_manager = ConfigManager(config_path=non_existent_path)
    config = config_manager.load_config()

    # Should return default config
    assert isinstance(config, Config)
    assert config.output_format == "human"
    assert config.reporting_mode == "dense"
    assert config.force_internet is False
    assert config.verbose is False


def test_config_file_invalid_json_raises_error():
    """Test that invalid JSON in config file raises appropriate error."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("{ invalid json }")
        config_file = f.name

    try:
        config_manager = ConfigManager(config_path=Path(config_file))

        with pytest.raises(ValueError, match="Invalid configuration file format"):
            config_manager.load_config()

    finally:
        Path(config_file).unlink(missing_ok=True)


def test_config_file_partial_settings():
    """Test that partial config file is merged with defaults."""
    # Create config with only some settings
    partial_config = {
        "output_format": "json",
        "verbose": True
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(partial_config, f)
        config_file = f.name

    try:
        config_manager = ConfigManager(config_path=Path(config_file))
        config = config_manager.load_config()

        # Specified settings should be loaded
        assert config.output_format == "json"
        assert config.verbose is True

        # Unspecified settings should use defaults
        assert config.reporting_mode == "dense"
        assert config.force_internet is False

    finally:
        Path(config_file).unlink(missing_ok=True)


def test_config_roundtrip_preserves_all_settings():
    """Test that saving and loading config preserves all settings."""
    # Create a config with all settings specified
    original_config = Config(
        database_path=Path("/tmp/test.db"),
        output_format="html",
        reporting_mode="full-err",
        force_internet=True,
        enabled_modules={
            "classification": True,
            "local_info": False,
            "internet_info": True,
            "netbox": True,
            "checkmk": False,
            "openitcockpit": False,
            "openvas": True,
            "infoblox": False,
        },
        verbose=True
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_file = f.name

    try:
        # Save config
        config_manager = ConfigManager(config_path=Path(config_file))
        config_manager.save_config(original_config)

        # Load config
        loaded_config = config_manager.load_config()

        # Verify all settings are preserved
        assert loaded_config.database_path == original_config.database_path
        assert loaded_config.output_format == original_config.output_format
        assert loaded_config.reporting_mode == original_config.reporting_mode
        assert loaded_config.force_internet == original_config.force_internet
        assert loaded_config.verbose == original_config.verbose
        assert loaded_config.enabled_modules == original_config.enabled_modules

    finally:
        Path(config_file).unlink(missing_ok=True)
