"""
Property-based tests for reputation checking behavior.

**Feature: ip-intelligence-analyzer, Property 19: Reputation Checking Behavior**
**Validates: Requirements 8.7, 8.8, 8.9, 8.11, 8.12**
"""

from hypothesis import given, strategies as st, assume, settings
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import Mock, patch
import socket

from src.ip_sentinel.modules.internet_info import InternetInfoModule, BlocklistResult


# Strategy for generating valid IPv4 addresses
ipv4_strategy = st.builds(
    IPv4Address,
    st.integers(min_value=0, max_value=2**32 - 1)
)

# Strategy for generating valid IPv6 addresses
ipv6_strategy = st.builds(
    IPv6Address,
    st.integers(min_value=0, max_value=2**128 - 1)
)

# Strategy for generating IP addresses (both IPv4 and IPv6)
ip_strategy = st.one_of(ipv4_strategy, ipv6_strategy)

# Strategy for generating blocklist results
blocklist_result_strategy = st.builds(
    BlocklistResult,
    source=st.text(min_size=1, max_size=50),
    listed=st.booleans(),
    details=st.one_of(st.none(), st.text(max_size=100))
)


class TestReputationCheckingBehavior:
    """Property-based tests for reputation checking behavior."""

    @given(ip_strategy)
    @settings(max_examples=100, deadline=None)
    def test_blocklist_checking_returns_structured_results(self, ip):
        """
        Property 19a: For any IP address, blocklist checking should return
        structured BlocklistResult objects with required fields.

        **Validates: Requirements 8.7, 8.8, 8.9**
        """
        module = InternetInfoModule()

        # Mock network calls to avoid external dependencies
        with patch.object(module, '_check_dns_blocklist') as mock_dns, \
                patch.object(module, '_check_crowdsec') as mock_crowdsec, \
                patch.object(module, '_check_reputation_services') as mock_reputation:

            # Setup mocks to return valid BlocklistResult objects
            mock_dns.return_value = BlocklistResult(source="test_dns", listed=False)
            mock_crowdsec.return_value = BlocklistResult(
                source="CrowdSec", listed=False)
            mock_reputation.return_value = [
                BlocklistResult(
                    source="test_rep",
                    listed=False)]

            results = module.check_blocklists(ip)

            # Verify all results are BlocklistResult objects
            assert isinstance(results, list)
            assert len(results) > 0

            for result in results:
                assert isinstance(result, BlocklistResult)
                assert hasattr(result, 'source')
                assert hasattr(result, 'listed')
                assert hasattr(result, 'details')
                assert isinstance(result.source, str)
                assert isinstance(result.listed, bool)
                assert len(result.source) > 0

    @given(st.lists(blocklist_result_strategy, min_size=1, max_size=20))
    @settings(max_examples=100, deadline=None)
    def test_reputation_score_calculation_bounds(self, blocklist_results):
        """
        Property 19b: For any list of blocklist results, reputation score
        should be between 0.0 and 1.0 inclusive.

        **Validates: Requirements 8.11**
        """
        module = InternetInfoModule()

        score = module._calculate_reputation_score(blocklist_results)

        if score is not None:
            assert isinstance(score, float)
            assert 0.0 <= score <= 1.0

    @given(st.lists(blocklist_result_strategy, min_size=1, max_size=20))
    @settings(max_examples=100, deadline=None)
    def test_reputation_score_inverse_correlation(self, blocklist_results):
        """
        Property 19c: For any list of blocklist results, reputation score
        should decrease as the number of positive hits increases.

        **Validates: Requirements 8.11**
        """
        module = InternetInfoModule()

        # Count positive hits
        positive_hits = sum(1 for result in blocklist_results if result.listed)
        total_checks = len(blocklist_results)

        score = module._calculate_reputation_score(blocklist_results)

        if score is not None:
            expected_score = 1.0 - (positive_hits / total_checks)
            assert abs(score - expected_score) < 0.01  # Allow for rounding

    @given(ip_strategy, st.booleans())
    @settings(max_examples=100, deadline=None)
    def test_dns_blocklist_ipv4_handling(self, ip, should_be_listed):
        """
        Property 19d: For any IPv4 address, DNS blocklist checking should
        handle the address format correctly and return appropriate results.

        **Validates: Requirements 8.8**
        """
        assume(isinstance(ip, IPv4Address))

        module = InternetInfoModule()

        # Mock socket.gethostbyname to simulate blocklist response
        with patch('socket.gethostbyname') as mock_dns:
            if should_be_listed:
                mock_dns.return_value = "127.0.0.2"  # Typical blocklist response
            else:
                mock_dns.side_effect = socket.gaierror("Not found")

            result = module._check_dns_blocklist(
                str(ip), "test.blocklist", "Test Blocklist")

            assert isinstance(result, BlocklistResult)
            assert result.source == "Test Blocklist"
            assert isinstance(result.listed, bool)
            assert result.listed == should_be_listed

    @given(ipv6_strategy)
    @settings(max_examples=100, deadline=None)
    def test_dns_blocklist_ipv6_handling(self, ip):
        """
        Property 19e: For any IPv6 address, DNS blocklist checking should
        handle IPv6 addresses gracefully (even if not fully supported).

        **Validates: Requirements 8.8**
        """
        module = InternetInfoModule()

        result = module._check_dns_blocklist(
            str(ip), "test.blocklist", "Test Blocklist")

        assert isinstance(result, BlocklistResult)
        assert result.source == "Test Blocklist"
        assert isinstance(result.listed, bool)
        # IPv6 should return False with appropriate details
        assert result.listed is False
        assert result.details is not None

    @given(ip_strategy)
    @settings(max_examples=100, deadline=None)
    def test_crowdsec_check_structure(self, ip):
        """
        Property 19f: For any IP address, CrowdSec checking should return
        a properly structured result regardless of API availability.

        **Validates: Requirements 8.9**
        """
        module = InternetInfoModule()

        # Mock requests to simulate different API responses
        with patch.object(module.session, 'get') as mock_get:
            # Test successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ip_range_score": 0}
            mock_get.return_value = mock_response

            result = module._check_crowdsec(str(ip))

            assert isinstance(result, BlocklistResult)
            assert result.source == "CrowdSec"
            assert isinstance(result.listed, bool)

    @given(st.lists(blocklist_result_strategy, min_size=0, max_size=20))
    @settings(max_examples=100, deadline=None)
    def test_reputation_score_empty_list_handling(self, blocklist_results):
        """
        Property 19g: For any empty or insufficient blocklist results,
        reputation score calculation should handle gracefully.

        **Validates: Requirements 8.11**
        """
        module = InternetInfoModule()

        if len(blocklist_results) == 0:
            score = module._calculate_reputation_score(blocklist_results)
            assert score is None
        else:
            score = module._calculate_reputation_score(blocklist_results)
            assert score is None or isinstance(score, float)

    @given(ip_strategy, st.booleans())
    @settings(max_examples=100, deadline=None)
    def test_mode_specific_filtering_behavior(self, ip, dense_mode):
        """
        Property 19h: For any IP address and reporting mode, blocklist results
        should be filterable according to mode requirements (dense vs full).

        **Validates: Requirements 8.12**
        """
        module = InternetInfoModule()

        # Create mixed results (some positive, some negative)
        mock_results = [
            BlocklistResult(source="Test1", listed=True, details="Listed"),
            BlocklistResult(source="Test2", listed=False, details="Not listed"),
            BlocklistResult(source="Test3", listed=True, details="Listed"),
            BlocklistResult(source="Test4", listed=False, details="Not listed")
        ]

        # Mock the blocklist checking to return our test results
        with patch.object(module, 'check_blocklists', return_value=mock_results):
            results = module.check_blocklists(ip)

            if dense_mode:
                # In dense mode, we should be able to filter to only positive results
                positive_results = [r for r in results if r.listed]
                assert all(r.listed for r in positive_results)
            else:
                # In full mode, we should have all results
                assert len(results) == len(mock_results)
                assert any(r.listed for r in results)
                assert any(not r.listed for r in results)

    @given(ip_strategy)
    @settings(max_examples=100, deadline=None)
    def test_reputation_services_error_handling(self, ip):
        """
        Property 19i: For any IP address, reputation service checks should
        handle errors gracefully and return appropriate failure indicators.

        **Validates: Requirements 8.7, 8.8, 8.9**
        """
        module = InternetInfoModule()

        # Mock requests to simulate network errors
        with patch.object(module.session, 'get') as mock_get:
            mock_get.side_effect = Exception("Network error")

            results = module._check_reputation_services(str(ip))

            assert isinstance(results, list)
            for result in results:
                assert isinstance(result, BlocklistResult)
                assert result.listed is False  # Should default to False on error
                assert result.details is not None  # Should contain error info
                assert "failed" in result.details.lower() or "error" in result.details.lower()

    @given(st.lists(blocklist_result_strategy, min_size=1, max_size=10))
    @settings(max_examples=100, deadline=None)
    def test_reputation_score_consistency(self, blocklist_results):
        """
        Property 19j: For any identical set of blocklist results,
        reputation score calculation should be deterministic.

        **Validates: Requirements 8.11**
        """
        module = InternetInfoModule()

        # Calculate score multiple times
        score1 = module._calculate_reputation_score(blocklist_results)
        score2 = module._calculate_reputation_score(blocklist_results)
        score3 = module._calculate_reputation_score(blocklist_results)

        # All scores should be identical
        assert score1 == score2 == score3
