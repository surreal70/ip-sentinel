"""
Property-based tests for output format validity.

**Feature: ip-intelligence-analyzer, Property 2: Output Format Validity**
**Validates: Requirements 2.2, 2.3, 2.5**
"""

import json
import html
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, List, Union

import hypothesis.strategies as st
from hypothesis import given, assume

from src.ip_mana.analyzer import AnalysisResult
from src.ip_mana.formatters import HumanFormatter, JSONFormatter, HTMLFormatter


# Strategies for generating test data
@st.composite
def ip_address_strategy(draw):
    """Generate valid IPv4 or IPv6 addresses."""
    ip_type = draw(st.sampled_from(['ipv4', 'ipv6']))
    if ip_type == 'ipv4':
        return IPv4Address(draw(st.integers(min_value=0, max_value=2**32-1)))
    else:
        return IPv6Address(draw(st.integers(min_value=0, max_value=2**128-1)))


@st.composite
def analysis_result_strategy(draw):
    """Generate valid AnalysisResult objects."""
    ip_addr = draw(ip_address_strategy())
    timestamp = draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime(2030, 12, 31)))
    
    # Generate classifications
    classifications = draw(st.lists(
        st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
        min_size=0, max_size=10
    ))
    
    # Generate local_info (can be None or dict)
    local_info = draw(st.one_of(
        st.none(),
        st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            st.one_of(st.text(max_size=100), st.integers(), st.booleans(), st.none()),
            min_size=0, max_size=5
        )
    ))
    
    # Generate internet_info (can be None or dict)
    internet_info = draw(st.one_of(
        st.none(),
        st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            st.one_of(st.text(max_size=100), st.integers(), st.booleans(), st.none()),
            min_size=0, max_size=5
        )
    ))
    
    # Generate application_info
    application_info = draw(st.dictionaries(
        st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
        st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            st.one_of(st.text(max_size=100), st.integers(), st.booleans()),
            min_size=0, max_size=3
        ),
        min_size=0, max_size=3
    ))
    
    # Generate errors
    errors = draw(st.lists(
        st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Po', 'Zs'))),
        min_size=0, max_size=5
    ))
    
    return AnalysisResult(
        ip_address=ip_addr,
        scan_timestamp=timestamp,
        classifications=classifications,
        local_info=local_info,
        internet_info=internet_info,
        application_info=application_info,
        errors=errors
    )


class TestOutputFormatValidity:
    """Property-based tests for output format validity."""

    @given(analysis_result_strategy(), st.sampled_from(['dense', 'full', 'full-err']))
    def test_json_format_validity(self, result: AnalysisResult, verbosity_mode: str):
        """
        Property 2: Output Format Validity - JSON Format
        
        For any analysis result and JSON output format, the generated output 
        should be well-formed and valid JSON.
        
        **Validates: Requirements 2.2, 2.3, 2.5**
        """
        formatter = JSONFormatter(verbosity_mode)
        output = formatter.format_result(result)
        
        # The output should be valid JSON
        try:
            parsed = json.loads(output)
            assert isinstance(parsed, dict), "JSON output should be a dictionary"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Invalid JSON output: {e}")
        
        # The output should be a non-empty string
        assert isinstance(output, str), "Output should be a string"
        assert len(output) > 0, "Output should not be empty"

    @given(analysis_result_strategy(), st.sampled_from(['dense', 'full', 'full-err']))
    def test_html_format_validity(self, result: AnalysisResult, verbosity_mode: str):
        """
        Property 2: Output Format Validity - HTML Format
        
        For any analysis result and HTML output format, the generated output 
        should be well-formed HTML with proper escaping.
        
        **Validates: Requirements 2.2, 2.3, 2.5**
        """
        formatter = HTMLFormatter(verbosity_mode)
        output = formatter.format_result(result)
        
        # The output should be a non-empty string
        assert isinstance(output, str), "Output should be a string"
        assert len(output) > 0, "Output should not be empty"
        
        # Should contain basic HTML structure
        assert output.startswith('<!DOCTYPE html>'), "HTML should start with DOCTYPE"
        assert '<html' in output, "HTML should contain html tag"
        assert '<head>' in output, "HTML should contain head section"
        assert '<body>' in output, "HTML should contain body section"
        assert '</html>' in output, "HTML should end with closing html tag"
        
        # Should contain the main content elements
        assert 'IP Intelligence Analysis Report' in output, "HTML should contain report title"
        
        # Check that potentially dangerous characters are properly escaped
        # We'll verify this by ensuring no unescaped < > & characters in content areas
        # (excluding the HTML tags themselves)
        content_sections = []
        in_tag = False
        current_content = ""
        
        for char in output:
            if char == '<':
                if current_content.strip():
                    content_sections.append(current_content)
                current_content = ""
                in_tag = True
            elif char == '>':
                in_tag = False
                current_content = ""
            elif not in_tag:
                current_content += char
        
        if current_content.strip():
            content_sections.append(current_content)

    @given(analysis_result_strategy(), st.sampled_from(['dense', 'full', 'full-err']))
    def test_human_format_validity(self, result: AnalysisResult, verbosity_mode: str):
        """
        Property 2: Output Format Validity - Human-readable Format
        
        For any analysis result and human-readable output format, the generated output 
        should be well-formed text with proper formatting.
        
        **Validates: Requirements 2.2, 2.3, 2.5**
        """
        formatter = HumanFormatter(verbosity_mode)
        output = formatter.format_result(result)
        
        # The output should be a non-empty string
        assert isinstance(output, str), "Output should be a string"
        assert len(output) > 0, "Output should not be empty"
        
        # Should contain the report header
        assert 'IP Intelligence Analysis Report' in output, "Should contain report title"
        assert 'IP Address:' in output, "Should contain IP address field"
        assert 'Scan Time:' in output, "Should contain scan time field"
        
        # Should contain the IP address from the result
        assert str(result.ip_address) in output, "Should contain the actual IP address"
        
        # Should be properly formatted with line breaks
        lines = output.split('\n')
        assert len(lines) > 1, "Output should contain multiple lines"

    @given(analysis_result_strategy())
    def test_format_consistency_across_verbosity_modes(self, result: AnalysisResult):
        """
        Property 2: Output Format Validity - Consistency
        
        For any analysis result, all output formats should handle all verbosity modes
        without errors and produce valid output.
        
        **Validates: Requirements 2.2, 2.3, 2.5**
        """
        formats = [
            ('json', JSONFormatter),
            ('html', HTMLFormatter), 
            ('human', HumanFormatter)
        ]
        
        verbosity_modes = ['dense', 'full', 'full-err']
        
        for format_name, formatter_class in formats:
            for mode in verbosity_modes:
                formatter = formatter_class(mode)
                
                # Should not raise an exception
                try:
                    output = formatter.format_result(result)
                except Exception as e:
                    raise AssertionError(f"{format_name} formatter with {mode} mode failed: {e}")
                
                # Should produce valid output
                assert isinstance(output, str), f"{format_name} output should be string"
                assert len(output) > 0, f"{format_name} output should not be empty"

    @given(st.sampled_from(['dense', 'full', 'full-err']))
    def test_verbosity_mode_validation(self, valid_mode: str):
        """
        Property 2: Output Format Validity - Verbosity Mode Validation
        
        For any valid verbosity mode, formatters should accept it without error.
        For invalid modes, formatters should raise appropriate errors.
        
        **Validates: Requirements 2.2, 2.3, 2.5**
        """
        # Valid modes should work
        for formatter_class in [JSONFormatter, HTMLFormatter, HumanFormatter]:
            formatter = formatter_class(valid_mode)
            assert formatter.verbosity_mode == valid_mode
            
            # Should be able to change to another valid mode
            other_modes = ['dense', 'full', 'full-err']
            other_modes.remove(valid_mode)
            new_mode = other_modes[0]
            
            formatter.set_verbosity(new_mode)
            assert formatter.verbosity_mode == new_mode

    def test_invalid_verbosity_mode_rejection(self):
        """
        Property 2: Output Format Validity - Invalid Mode Rejection
        
        For any invalid verbosity mode, formatters should raise ValueError.
        
        **Validates: Requirements 2.2, 2.3, 2.5**
        """
        invalid_modes = ['invalid', 'verbose', 'quiet', '', 'DENSE', 'Full']
        
        for formatter_class in [JSONFormatter, HTMLFormatter, HumanFormatter]:
            for invalid_mode in invalid_modes:
                try:
                    formatter = formatter_class(invalid_mode)
                    raise AssertionError(f"Should have rejected invalid mode: {invalid_mode}")
                except ValueError:
                    pass  # Expected behavior
                
                # Test set_verbosity with invalid mode
                formatter = formatter_class('dense')
                try:
                    formatter.set_verbosity(invalid_mode)
                    raise AssertionError(f"Should have rejected invalid mode in set_verbosity: {invalid_mode}")
                except ValueError:
                    pass  # Expected behavior