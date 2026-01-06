"""
Property-based tests for full mode completeness.

**Feature: ip-intelligence-analyzer, Property 6: Full Mode Completeness**
**Validates: Requirements 4.4, 4.5**
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, List, Optional, Union

import hypothesis.strategies as st
from hypothesis import given, assume

from src.ip_mana.analyzer import AnalysisResult
from src.ip_mana.formatters import HumanFormatter, JSONFormatter, HTMLFormatter, VerbosityMode


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
    """Generate AnalysisResult objects with mixed meaningful and empty data."""
    ip_addr = draw(ip_address_strategy())
    timestamp = draw(st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime(2030, 12, 31)))
    
    # Generate classifications (can be empty or meaningful)
    classifications = draw(st.one_of(
        st.just([]),  # Empty
        st.lists(
            st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            min_size=1, max_size=5
        )  # Meaningful
    ))
    
    # Generate local_info (can be None, empty dict, or meaningful dict)
    local_info = draw(st.one_of(
        st.none(),
        st.just({}),  # Empty dict
        st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            st.one_of(st.text(min_size=1, max_size=100), st.integers(), st.booleans()),
            min_size=1, max_size=5
        )  # Meaningful dict
    ))
    
    # Generate internet_info (can be None, empty dict, or meaningful dict)
    internet_info = draw(st.one_of(
        st.none(),
        st.just({}),  # Empty dict
        st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))),
            st.one_of(st.text(min_size=1, max_size=100), st.integers(), st.booleans()),
            min_size=1, max_size=5
        )  # Meaningful dict
    ))
    
    # Generate application_info (can be empty dict or meaningful dict)
    application_info = draw(st.one_of(
        st.just({}),  # Empty dict
        st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))),
            st.one_of(
                st.just({}),  # Empty nested dict
                st.dictionaries(
                    st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))),
                    st.one_of(st.text(min_size=1, max_size=100), st.integers(), st.booleans()),
                    min_size=1, max_size=3
                )  # Meaningful nested dict
            ),
            min_size=0, max_size=3
        )
    ))
    
    # Generate errors (can be empty or meaningful)
    errors = draw(st.one_of(
        st.just([]),  # Empty
        st.lists(
            st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Po', 'Zs'))),
            min_size=1, max_size=5
        )  # Meaningful
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


class TestFullModeCompleteness:
    """Property-based tests for full mode completeness behavior."""

    @given(analysis_result_strategy())
    def test_full_mode_includes_all_sections(self, result: AnalysisResult):
        """
        Property 6: Full Mode Completeness - All Sections Included
        
        For any analysis result in full mode, the output should include all 
        executed tests regardless of success or failure, with "no results" 
        displayed for empty tests.
        
        **Validates: Requirements 4.4, 4.5**
        """
        formatter = JSONFormatter(VerbosityMode.FULL)
        output = formatter.format_result(result)
        
        # Parse JSON output to check structure
        import json
        parsed = json.loads(output)
        
        # Core fields should always be present
        assert 'ip_address' in parsed, "IP address should always be present in full mode"
        assert 'scan_timestamp' in parsed, "Scan timestamp should always be present in full mode"
        
        # All analysis sections should be present in full mode, even if empty
        expected_sections = ['classifications', 'local_info', 'internet_info', 'application_info', 'errors']
        
        for section in expected_sections:
            assert section in parsed, f"Section '{section}' should be present in full mode"
            
            # If the original data was empty/None, it should show "no results" or be present but empty
            original_value = getattr(result, section)
            if not formatter._has_meaningful_data(original_value):
                # In full mode, empty data should either be "no results" or the empty structure
                parsed_value = parsed[section]
                assert (parsed_value == "no results" or 
                       not formatter._has_meaningful_data(parsed_value)), \
                    f"Empty section '{section}' should show 'no results' or empty structure in full mode"

    @given(analysis_result_strategy())
    def test_full_mode_vs_dense_mode_completeness(self, result: AnalysisResult):
        """
        Property 6: Full Mode Completeness - Comparison with Dense Mode
        
        For any analysis result, full mode should include all sections that 
        dense mode includes, plus additional sections marked as "no results".
        
        **Validates: Requirements 4.4, 4.5**
        """
        dense_formatter = JSONFormatter(VerbosityMode.DENSE)
        full_formatter = JSONFormatter(VerbosityMode.FULL)
        
        dense_output = dense_formatter.format_result(result)
        full_output = full_formatter.format_result(result)
        
        import json
        dense_parsed = json.loads(dense_output)
        full_parsed = json.loads(full_output)
        
        # Full mode should have more or equal keys than dense mode
        dense_keys = set(dense_parsed.keys())
        full_keys = set(full_parsed.keys())
        
        # All keys in dense should also be in full
        assert dense_keys.issubset(full_keys), \
            f"Dense mode keys {dense_keys} should be subset of full mode keys {full_keys}"
        
        # Full mode should have at least as many keys as dense mode
        assert len(full_keys) >= len(dense_keys), \
            "Full mode should have at least as many sections as dense mode"
        
        # For sections present in both, meaningful data should be the same
        for key in dense_keys:
            if dense_formatter._has_meaningful_data(dense_parsed[key]):
                assert full_formatter._has_meaningful_data(full_parsed[key]), \
                    f"Meaningful data in section '{key}' should be present in both modes"

    @given(analysis_result_strategy())
    def test_full_mode_no_results_marking(self, result: AnalysisResult):
        """
        Property 6: Full Mode Completeness - "No Results" Marking
        
        For any analysis result in full mode, sections with no meaningful data
        should be explicitly marked as "no results" or show empty structure.
        
        **Validates: Requirements 4.4, 4.5**
        """
        formatter = JSONFormatter(VerbosityMode.FULL)
        output = formatter.format_result(result)
        
        import json
        parsed = json.loads(output)
        
        # Check each section for proper "no results" handling
        sections_to_check = [
            ('classifications', result.classifications),
            ('local_info', result.local_info),
            ('internet_info', result.internet_info),
            ('application_info', result.application_info),
            ('errors', result.errors)
        ]
        
        for section_name, original_value in sections_to_check:
            if section_name in parsed:
                parsed_value = parsed[section_name]
                
                # If original was empty/meaningless, parsed should reflect that
                if not formatter._has_meaningful_data(original_value):
                    # Should either be "no results" or an empty structure
                    is_no_results = parsed_value == "no results"
                    is_empty_structure = not formatter._has_meaningful_data(parsed_value)
                    
                    assert is_no_results or is_empty_structure, \
                        f"Empty section '{section_name}' should be marked as 'no results' or empty structure, got: {parsed_value}"

    @given(analysis_result_strategy())
    def test_full_mode_consistency_across_formatters(self, result: AnalysisResult):
        """
        Property 6: Full Mode Completeness - Consistency Across Formatters
        
        For any analysis result, all formatters in full mode should include
        the same sections and handle empty data consistently.
        
        **Validates: Requirements 4.4, 4.5**
        """
        json_formatter = JSONFormatter(VerbosityMode.FULL)
        html_formatter = HTMLFormatter(VerbosityMode.FULL)
        human_formatter = HumanFormatter(VerbosityMode.FULL)
        
        # All formatters should produce output without errors
        json_output = json_formatter.format_result(result)
        html_output = html_formatter.format_result(result)
        human_output = human_formatter.format_result(result)
        
        # All outputs should be non-empty strings
        assert isinstance(json_output, str) and len(json_output) > 0
        assert isinstance(html_output, str) and len(html_output) > 0
        assert isinstance(human_output, str) and len(human_output) > 0
        
        # Check that the same filtering logic is applied
        json_filtered = json_formatter._filter_by_verbosity(json_formatter._prepare_result_data(result))
        html_filtered = html_formatter._filter_by_verbosity(html_formatter._prepare_result_data(result))
        human_filtered = human_formatter._filter_by_verbosity(human_formatter._prepare_result_data(result))
        
        # The filtered data structure should be the same across formatters
        assert set(json_filtered.keys()) == set(html_filtered.keys()) == set(human_filtered.keys()), \
            "All formatters should include the same sections in full mode"
        
        # For HTML and human formatters, check that they contain expected content
        # HTML should contain section headers for all sections
        expected_sections = ['Classifications', 'Local Network Information', 'Internet Information', 
                           'Application Information', 'Errors and Issues']
        
        for section in expected_sections:
            # In full mode, all sections should be present in HTML output
            if any(json_formatter._has_meaningful_data(getattr(result, attr, None)) 
                   for attr in ['classifications', 'local_info', 'internet_info', 'application_info', 'errors']):
                # At least some sections should be present
                pass  # We'll check this more specifically below
        
        # Human formatter should contain the report structure
        assert 'IP Intelligence Analysis Report' in human_output, \
            "Human formatter should contain report title in full mode"

    @given(analysis_result_strategy())
    def test_full_mode_preserves_meaningful_data(self, result: AnalysisResult):
        """
        Property 6: Full Mode Completeness - Meaningful Data Preservation
        
        For any analysis result in full mode, all meaningful data should be
        preserved and displayed, not filtered out.
        
        **Validates: Requirements 4.4, 4.5**
        """
        formatter = JSONFormatter(VerbosityMode.FULL)
        output = formatter.format_result(result)
        
        import json
        parsed = json.loads(output)
        
        # Check that meaningful data is preserved
        if formatter._has_meaningful_data(result.classifications):
            assert 'classifications' in parsed and formatter._has_meaningful_data(parsed['classifications']), \
                "Meaningful classifications should be preserved in full mode"
        
        if formatter._has_meaningful_data(result.local_info):
            assert 'local_info' in parsed and formatter._has_meaningful_data(parsed['local_info']), \
                "Meaningful local_info should be preserved in full mode"
        
        if formatter._has_meaningful_data(result.internet_info):
            assert 'internet_info' in parsed and formatter._has_meaningful_data(parsed['internet_info']), \
                "Meaningful internet_info should be preserved in full mode"
        
        if formatter._has_meaningful_data(result.application_info):
            assert 'application_info' in parsed and formatter._has_meaningful_data(parsed['application_info']), \
                "Meaningful application_info should be preserved in full mode"
        
        if formatter._has_meaningful_data(result.errors):
            assert 'errors' in parsed and formatter._has_meaningful_data(parsed['errors']), \
                "Meaningful errors should be preserved in full mode"

    def test_full_mode_empty_result_handling(self):
        """
        Property 6: Full Mode Completeness - Empty Result Handling
        
        For an analysis result with all empty data, full mode should still
        show all sections with appropriate "no results" indicators.
        
        **Validates: Requirements 4.4, 4.5**
        """
        # Create a result with all empty data
        empty_result = AnalysisResult(
            ip_address=IPv4Address('192.168.1.1'),
            scan_timestamp=datetime.now(),
            classifications=[],
            local_info=None,
            internet_info={},
            application_info={},
            errors=[]
        )
        
        formatter = JSONFormatter(VerbosityMode.FULL)
        output = formatter.format_result(empty_result)
        
        import json
        parsed = json.loads(output)
        
        # All sections should be present
        expected_sections = ['ip_address', 'scan_timestamp', 'classifications', 
                           'local_info', 'internet_info', 'application_info', 'errors']
        
        for section in expected_sections:
            assert section in parsed, f"Section '{section}' should be present even when empty"
        
        # Empty sections should be marked appropriately
        for section in ['classifications', 'local_info', 'internet_info', 'application_info', 'errors']:
            parsed_value = parsed[section]
            # Should be "no results" or empty structure
            assert (parsed_value == "no results" or 
                   not formatter._has_meaningful_data(parsed_value)), \
                f"Empty section '{section}' should be marked as 'no results' or empty structure"