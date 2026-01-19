"""
Property-based tests for dense mode filtering.

**Feature: ip-intelligence-analyzer, Property 5: Dense Mode Filtering**
**Validates: Requirements 4.2**
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

import hypothesis.strategies as st
from hypothesis import given

from src.ip_sentinel.analyzer import AnalysisResult
from src.ip_sentinel.formatters import HumanFormatter, JSONFormatter, HTMLFormatter, VerbosityMode


# Strategies for generating test data with controlled empty/meaningful data
@st.composite
def ip_address_strategy(draw):
    """Generate valid IPv4 or IPv6 addresses."""
    ip_type = draw(st.sampled_from(['ipv4', 'ipv6']))
    if ip_type == 'ipv4':
        return IPv4Address(draw(st.integers(min_value=0, max_value=2**32 - 1)))
    else:
        return IPv6Address(draw(st.integers(min_value=0, max_value=2**128 - 1)))


@st.composite
def meaningful_data_strategy(draw):
    """Generate data that should be considered meaningful."""
    return draw(
        st.one_of(
            st.text(
                min_size=1,
                max_size=50,
                alphabet=st.characters(
                    whitelist_categories=(
                        'Lu',
                        'Ll',
                        'Nd',
                        'Pc',
                        'Pd'))),
            st.integers(
                min_value=-1000,
                max_value=1000),
            st.booleans(),
            st.lists(
                st.text(
                    min_size=1,
                    max_size=20),
                min_size=1,
                max_size=5),
            st.dictionaries(
                st.text(
                    min_size=1,
                    max_size=10,
                    alphabet=st.characters(
                        whitelist_categories=(
                            'Lu',
                            'Ll',
                            'Nd'))),
                st.text(
                    min_size=1,
                    max_size=20),
                min_size=1,
                max_size=3)))


@st.composite
def empty_data_strategy(draw):
    """Generate data that should be considered empty/meaningless."""
    return draw(
        st.one_of(
            st.none(), st.just(""), st.just(
                []), st.just(
                {}), st.dictionaries(
                    st.text(
                        min_size=1, max_size=10), st.one_of(
                            st.none(), st.just(""), st.just(
                                []), st.just(
                                    {})), min_size=1, max_size=3), st.lists(
                                        st.one_of(
                                            st.none(), st.just(""), st.just(
                                                []), st.just(
                                                    {})), min_size=1, max_size=3)))


@st.composite
def mixed_data_strategy(draw):
    """Generate data that mixes meaningful and empty data."""
    return draw(st.one_of(meaningful_data_strategy(), empty_data_strategy()))


@st.composite
def analysis_result_with_controlled_data(draw, has_meaningful_data: bool = True):
    """Generate AnalysisResult with controlled meaningful/empty data."""
    ip_addr = draw(ip_address_strategy())
    timestamp = draw(
        st.datetimes(
            min_value=datetime(
                2020, 1, 1), max_value=datetime(
                2030, 12, 31)))

    # Generate classifications
    if has_meaningful_data:
        classifications = draw(
            st.lists(
                st.text(
                    min_size=1,
                    max_size=50,
                    alphabet=st.characters(
                        whitelist_categories=(
                            'Lu',
                            'Ll',
                            'Nd',
                            'Pc',
                            'Pd'))),
                min_size=1,
                max_size=5))
    else:
        classifications = draw(st.one_of(
            st.just([]),
            st.just(None),
            st.lists(st.just(""), min_size=0, max_size=2)
        ))

    # Ensure classifications is a list
    if classifications is None:
        classifications = []

    # Generate other fields
    if has_meaningful_data:
        local_info = draw(
            st.one_of(
                st.none(),
                st.dictionaries(
                    st.text(
                        min_size=1,
                        max_size=20,
                        alphabet=st.characters(
                            whitelist_categories=(
                                'Lu',
                                'Ll',
                                'Nd',
                                'Pc'))),
                    st.one_of(
                        st.text(
                            min_size=1,
                            max_size=100),
                        st.integers(),
                        st.booleans()),
                    min_size=1,
                    max_size=5)))
        internet_info = draw(
            st.one_of(
                st.none(),
                st.dictionaries(
                    st.text(
                        min_size=1,
                        max_size=20,
                        alphabet=st.characters(
                            whitelist_categories=(
                                'Lu',
                                'Ll',
                                'Nd',
                                'Pc'))),
                    st.one_of(
                        st.text(
                            min_size=1,
                            max_size=100),
                        st.integers(),
                        st.booleans()),
                    min_size=1,
                    max_size=5)))
    else:
        local_info = draw(st.one_of(st.none(), st.just({})))
        internet_info = draw(st.one_of(st.none(), st.just({})))

    # Generate application_info
    if has_meaningful_data:
        application_info = draw(
            st.dictionaries(
                st.text(
                    min_size=1,
                    max_size=20,
                    alphabet=st.characters(
                        whitelist_categories=(
                            'Lu',
                            'Ll',
                            'Nd'))),
                st.dictionaries(
                    st.text(
                        min_size=1,
                        max_size=20,
                        alphabet=st.characters(
                            whitelist_categories=(
                                'Lu',
                                'Ll',
                                'Nd'))),
                    st.one_of(
                        st.text(
                            min_size=1,
                            max_size=100),
                        st.integers(),
                        st.booleans()),
                    min_size=1,
                    max_size=3),
                min_size=0,
                max_size=3))
    else:
        application_info = draw(st.one_of(
            st.just({}),
            st.dictionaries(
                st.text(min_size=1, max_size=20),
                st.just({}),
                min_size=1, max_size=2
            )
        ))

    # Generate errors
    if has_meaningful_data:
        errors = draw(
            st.lists(
                st.text(
                    min_size=1,
                    max_size=100,
                    alphabet=st.characters(
                        whitelist_categories=(
                            'Lu',
                            'Ll',
                            'Nd',
                            'Pc',
                            'Pd',
                            'Po',
                            'Zs'))),
                min_size=0,
                max_size=5))
    else:
        errors = draw(st.one_of(
            st.just([]),
            st.lists(st.just(""), min_size=0, max_size=2)
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


class TestDenseModeFiltering:
    """Property-based tests for dense mode filtering behavior."""

    @given(analysis_result_with_controlled_data(has_meaningful_data=True))
    def test_dense_mode_includes_meaningful_data(self, result: AnalysisResult):
        """
        Property 5: Dense Mode Filtering - Meaningful Data Inclusion

        For any analysis result with meaningful data in dense mode,
        the output should contain only sections with collected information.

        **Validates: Requirements 4.2**
        """
        # Test with all formatter types
        formatters = [
            ('json', JSONFormatter(VerbosityMode.DENSE)),
            ('html', HTMLFormatter(VerbosityMode.DENSE)),
            ('human', HumanFormatter(VerbosityMode.DENSE))
        ]

        for format_name, formatter in formatters:
            output = formatter.format_result(result)

            # Output should not be empty
            assert len(output) > 0, f"{format_name} output should not be empty"

            # For JSON, we can parse and check the structure
            if format_name == 'json':
                import json
                parsed = json.loads(output)

                # Check that meaningful data is present
                if formatter._has_meaningful_data(result.classifications):
                    assert 'classifications' in parsed, "Classifications should be included when meaningful"

                if formatter._has_meaningful_data(result.local_info):
                    assert 'local_info' in parsed, "Local info should be included when meaningful"

                if formatter._has_meaningful_data(result.internet_info):
                    assert 'internet_info' in parsed, "Internet info should be included when meaningful"

                if formatter._has_meaningful_data(result.application_info):
                    assert 'application_info' in parsed, "Application info should be included when meaningful"

                if formatter._has_meaningful_data(result.errors):
                    assert 'errors' in parsed, "Errors should be included when meaningful"

    @given(analysis_result_with_controlled_data(has_meaningful_data=False))
    def test_dense_mode_excludes_empty_data(self, result: AnalysisResult):
        """
        Property 5: Dense Mode Filtering - Empty Data Exclusion

        For any analysis result with only empty data in dense mode,
        the output should exclude sections with no meaningful information.

        **Validates: Requirements 4.2**
        """
        formatter = JSONFormatter(VerbosityMode.DENSE)
        output = formatter.format_result(result)

        # Parse JSON output to check structure
        import json
        parsed = json.loads(output)

        # Basic fields should always be present
        assert 'ip_address' in parsed, "IP address should always be present"
        assert 'scan_timestamp' in parsed, "Scan timestamp should always be present"

        # Empty data should be filtered out in dense mode
        if not formatter._has_meaningful_data(result.classifications):
            assert 'classifications' not in parsed or not formatter._has_meaningful_data(
                parsed.get('classifications')), "Empty classifications should be filtered out in dense mode"

        if not formatter._has_meaningful_data(result.local_info):
            assert 'local_info' not in parsed or not formatter._has_meaningful_data(
                parsed.get('local_info')), "Empty local_info should be filtered out in dense mode"

        if not formatter._has_meaningful_data(result.internet_info):
            assert 'internet_info' not in parsed or not formatter._has_meaningful_data(
                parsed.get('internet_info')), "Empty internet_info should be filtered out in dense mode"

        if not formatter._has_meaningful_data(result.application_info):
            assert 'application_info' not in parsed or not formatter._has_meaningful_data(parsed.get(
                'application_info')), "Empty application_info should be filtered out in dense mode"

        if not formatter._has_meaningful_data(result.errors):
            assert 'errors' not in parsed or not formatter._has_meaningful_data(
                parsed.get('errors')), "Empty errors should be filtered out in dense mode"

    @given(st.data())
    def test_dense_vs_full_mode_difference(self, data):
        """
        Property 5: Dense Mode Filtering - Dense vs Full Mode Comparison

        For any analysis result, dense mode should show fewer or equal sections
        compared to full mode, excluding empty data that full mode includes.

        **Validates: Requirements 4.2**
        """
        # Generate a result with mixed meaningful and empty data
        result = data.draw(
            analysis_result_with_controlled_data(
                has_meaningful_data=data.draw(
                    st.booleans())))

        dense_formatter = JSONFormatter(VerbosityMode.DENSE)
        full_formatter = JSONFormatter(VerbosityMode.FULL)

        dense_output = dense_formatter.format_result(result)
        full_output = full_formatter.format_result(result)

        import json
        dense_parsed = json.loads(dense_output)
        full_parsed = json.loads(full_output)

        # Dense mode should have fewer or equal keys than full mode
        dense_keys = set(dense_parsed.keys())
        full_keys = set(full_parsed.keys())

        # All keys in dense should also be in full
        assert dense_keys.issubset(full_keys), \
            f"Dense mode keys {dense_keys} should be subset of full mode keys {full_keys}"

        # Core fields should be in both
        core_fields = {'ip_address', 'scan_timestamp'}
        assert core_fields.issubset(dense_keys), "Core fields should be in dense mode"
        assert core_fields.issubset(full_keys), "Core fields should be in full mode"

    @given(analysis_result_with_controlled_data())
    def test_dense_mode_consistency_across_formatters(self, result: AnalysisResult):
        """
        Property 5: Dense Mode Filtering - Consistency Across Formatters

        For any analysis result, all formatters in dense mode should apply
        the same filtering logic for meaningful vs empty data.

        **Validates: Requirements 4.2**
        """
        json_formatter = JSONFormatter(VerbosityMode.DENSE)
        html_formatter = HTMLFormatter(VerbosityMode.DENSE)
        human_formatter = HumanFormatter(VerbosityMode.DENSE)

        # All formatters should produce output without errors
        json_output = json_formatter.format_result(result)
        html_output = html_formatter.format_result(result)
        human_output = human_formatter.format_result(result)

        # All outputs should be non-empty strings
        assert isinstance(json_output, str) and len(json_output) > 0
        assert isinstance(html_output, str) and len(html_output) > 0
        assert isinstance(human_output, str) and len(human_output) > 0

        # Check that the same filtering logic is applied
        # We can verify this by checking the filtered data from the base formatter
        json_filtered = json_formatter._filter_by_verbosity(
            json_formatter._prepare_result_data(result))
        html_filtered = html_formatter._filter_by_verbosity(
            html_formatter._prepare_result_data(result))
        human_filtered = human_formatter._filter_by_verbosity(
            human_formatter._prepare_result_data(result))

        # The filtered data structure should be the same across formatters
        assert set(json_filtered.keys()) == set(html_filtered.keys()) == set(
            human_filtered.keys()), "All formatters should filter the same fields in dense mode"

    def test_meaningful_data_detection_edge_cases(self):
        """
        Property 5: Dense Mode Filtering - Edge Cases for Meaningful Data Detection

        Test edge cases for what constitutes meaningful vs empty data.

        **Validates: Requirements 4.2**
        """
        formatter = JSONFormatter(VerbosityMode.DENSE)

        # Test various edge cases
        test_cases = [
            # Empty cases
            (None, False, "None should not be meaningful"),
            ("", False, "Empty string should not be meaningful"),
            ([], False, "Empty list should not be meaningful"),
            ({}, False, "Empty dict should not be meaningful"),
            ({"key": None}, False, "Dict with None values should not be meaningful"),
            ({"key": ""}, False, "Dict with empty string values should not be meaningful"),
            ({"key": []}, False, "Dict with empty list values should not be meaningful"),
            ([None, "", []], False, "List with empty values should not be meaningful"),

            # Meaningful cases
            ("text", True, "Non-empty string should be meaningful"),
            (0, True, "Zero should be meaningful"),
            (False, True, "False boolean should be meaningful"),
            ([1, 2, 3], True, "Non-empty list should be meaningful"),
            ({"key": "value"}, True, "Dict with values should be meaningful"),
            ({"key": 0}, True, "Dict with zero should be meaningful"),
            ({"key": False}, True, "Dict with False should be meaningful"),
        ]

        for value, expected_meaningful, description in test_cases:
            actual_meaningful = formatter._has_meaningful_data(value)
            assert actual_meaningful == expected_meaningful, \
                f"{description}: expected {expected_meaningful}, got {actual_meaningful} for value {value}"
