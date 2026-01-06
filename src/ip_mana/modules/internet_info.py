"""
Internet Information Module (Module 3) for gathering public IP intelligence.
"""

import logging
import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, List, Optional, Union, Any
import requests
from ipwhois import IPWhois

# Type alias for IP addresses
IPAddress = Union[IPv4Address, IPv6Address]

logger = logging.getLogger(__name__)


@dataclass
class WhoisResult:
    """Result of WHOIS lookup."""
    network: Optional[str] = None
    country: Optional[str] = None
    org: Optional[str] = None
    description: Optional[str] = None
    emails: List[str] = None
    created: Optional[str] = None
    updated: Optional[str] = None
    raw_data: Dict[str, Any] = None


@dataclass
class GeolocationResult:
    """Result of geolocation lookup."""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    raw_data: Dict[str, Any] = None


@dataclass
class ASNResult:
    """Result of ASN lookup."""
    asn: Optional[str] = None
    description: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    raw_data: Dict[str, Any] = None


@dataclass
class BlocklistResult:
    """Result of blocklist check."""
    source: str
    listed: bool
    details: Optional[str] = None


@dataclass
class InternetInfoResult:
    """Complete internet information analysis result."""
    whois_data: WhoisResult
    geolocation: GeolocationResult
    asn_info: ASNResult
    blocklist_results: List[BlocklistResult]
    reputation_score: Optional[float] = None
    reverse_dns: Optional[str] = None


class InternetInfoModule:
    """Module for querying external services for public IP intelligence."""

    def __init__(self):
        """Initialize the internet info module."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'IP-ManA/1.0 (IP Intelligence Analyzer)'
        })
        
        # DNS resolvers for reverse lookup
        self.dns_resolvers = [
            '1.1.1.1',  # Cloudflare
            '8.8.8.8',  # Google
            '8.8.4.4'   # Google secondary
        ]

    def analyze(self, ip: IPAddress, mode: str = "dense") -> Dict:
        """
        Perform comprehensive internet-based analysis.

        Args:
            ip: IPAddress object to analyze
            mode: Reporting mode ("dense", "full", "full-err")

        Returns:
            Dictionary containing all internet analysis results
        """
        logger.info(f"Starting internet analysis for {ip}")
        
        # Perform WHOIS lookup
        whois_data = self.perform_whois_lookup(ip)
        
        # Perform reverse DNS lookup against internet resolvers
        reverse_dns = self.perform_reverse_dns_lookup(ip)
        
        # Get ASN information
        asn_info = self.get_asn_info(ip)
        
        # Get geolocation data
        geolocation = self.get_geolocation(ip)
        
        # Check blocklists
        blocklist_results = self.check_blocklists(ip)
        
        # Filter blocklist results based on mode (Requirements 8.11, 8.12)
        filtered_blocklist_results = self._filter_blocklist_results(blocklist_results, mode)
        
        # Calculate reputation score
        reputation_score = self._calculate_reputation_score(blocklist_results)
        
        # Convert to dictionary format for compatibility
        return {
            "whois_data": self._whois_to_dict(whois_data),
            "geolocation": self._geolocation_to_dict(geolocation),
            "asn_info": self._asn_to_dict(asn_info),
            "blocklist_results": [self._blocklist_to_dict(bl) for bl in filtered_blocklist_results],
            "reputation_score": reputation_score,
            "reverse_dns": reverse_dns
        }

    def perform_whois_lookup(self, ip: IPAddress) -> WhoisResult:
        """
        Perform WHOIS lookup and gather available information.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            WhoisResult with WHOIS data
        """
        try:
            whois = IPWhois(str(ip))
            result = whois.lookup_rdap(depth=1)
            
            # Extract relevant information
            network = result.get('network', {})
            
            whois_result = WhoisResult(
                network=network.get('cidr'),
                country=network.get('country'),
                org=result.get('asn_description'),
                description=network.get('name'),
                emails=self._extract_emails(result),
                created=network.get('start_date'),
                updated=network.get('end_date'),
                raw_data=result
            )
            
            logger.debug(f"WHOIS lookup successful for {ip}")
            return whois_result
            
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {ip}: {e}")
            return WhoisResult(raw_data={'error': str(e)})

    def perform_reverse_dns_lookup(self, ip: IPAddress) -> Optional[str]:
        """
        Perform reverse DNS lookup against internet resolvers and Hackertarget API.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Hostname if found, None otherwise
        """
        ip_str = str(ip)
        
        # Try standard reverse DNS first
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            logger.debug(f"Reverse DNS successful for {ip}: {hostname}")
            return hostname
        except Exception:
            pass
        
        # Try Hackertarget API
        try:
            response = self.session.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip_str}",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.text.strip()
                if result and not result.startswith("error"):
                    # Hackertarget returns multiple hostnames, take the first
                    hostnames = result.split('\n')
                    if hostnames and hostnames[0]:
                        logger.debug(f"Hackertarget reverse DNS successful for {ip}: {hostnames[0]}")
                        return hostnames[0]
        except Exception as e:
            logger.warning(f"Hackertarget reverse DNS failed for {ip}: {e}")
        
        logger.debug(f"No reverse DNS found for {ip}")
        return None

    def get_asn_info(self, ip: IPAddress) -> ASNResult:
        """
        Determine ASN (Autonomous System Number) ownership.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ASNResult with ASN information
        """
        try:
            whois = IPWhois(str(ip))
            result = whois.lookup_rdap(depth=1)
            
            asn_result = ASNResult(
                asn=result.get('asn'),
                description=result.get('asn_description'),
                country=result.get('asn_country_code'),
                registry=result.get('asn_registry'),
                raw_data=result
            )
            
            logger.debug(f"ASN lookup successful for {ip}")
            return asn_result
            
        except Exception as e:
            logger.warning(f"ASN lookup failed for {ip}: {e}")
            return ASNResult(raw_data={'error': str(e)})

    def get_geolocation(self, ip: IPAddress) -> GeolocationResult:
        """
        Gather geolocation data for IP address.
        
        Args:
            ip: IP address to geolocate
            
        Returns:
            GeolocationResult with location data
        """
        ip_str = str(ip)
        
        # Try multiple geolocation services
        services = [
            self._get_geolocation_ipapi,
            self._get_geolocation_ipinfo,
            self._get_geolocation_freegeoip
        ]
        
        for service in services:
            try:
                result = service(ip_str)
                if result and any(result.__dict__.values()):
                    logger.debug(f"Geolocation successful for {ip} via {service.__name__}")
                    return result
            except Exception as e:
                logger.warning(f"Geolocation service {service.__name__} failed for {ip}: {e}")
                continue
        
        logger.warning(f"All geolocation services failed for {ip}")
        return GeolocationResult(raw_data={'error': 'All services failed'})

    def _get_geolocation_ipapi(self, ip_str: str) -> GeolocationResult:
        """Get geolocation from ip-api.com (free tier)."""
        response = self.session.get(
            f"http://ip-api.com/json/{ip_str}",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return GeolocationResult(
                    country=data.get('country'),
                    country_code=data.get('countryCode'),
                    region=data.get('regionName'),
                    city=data.get('city'),
                    latitude=data.get('lat'),
                    longitude=data.get('lon'),
                    timezone=data.get('timezone'),
                    isp=data.get('isp'),
                    raw_data=data
                )
        
        return GeolocationResult()

    def _get_geolocation_ipinfo(self, ip_str: str) -> GeolocationResult:
        """Get geolocation from ipinfo.io (free tier)."""
        response = self.session.get(
            f"https://ipinfo.io/{ip_str}/json",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Parse location coordinates
            loc = data.get('loc', '').split(',')
            latitude = float(loc[0]) if len(loc) >= 2 and loc[0] else None
            longitude = float(loc[1]) if len(loc) >= 2 and loc[1] else None
            
            return GeolocationResult(
                country=data.get('country'),
                region=data.get('region'),
                city=data.get('city'),
                latitude=latitude,
                longitude=longitude,
                timezone=data.get('timezone'),
                isp=data.get('org'),
                raw_data=data
            )
        
        return GeolocationResult()

    def _get_geolocation_freegeoip(self, ip_str: str) -> GeolocationResult:
        """Get geolocation from freegeoip.app (backup service)."""
        response = self.session.get(
            f"https://freegeoip.app/json/{ip_str}",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            return GeolocationResult(
                country=data.get('country_name'),
                country_code=data.get('country_code'),
                region=data.get('region_name'),
                city=data.get('city'),
                latitude=data.get('latitude'),
                longitude=data.get('longitude'),
                timezone=data.get('time_zone'),
                raw_data=data
            )
        
        return GeolocationResult()

    def check_blocklists(self, ip: IPAddress) -> List[BlocklistResult]:
        """
        Check IP address against spam lists, DNS blocklists, and CrowdSec database.
        
        Args:
            ip: IP address to check
            
        Returns:
            List of BlocklistResult objects
        """
        results = []
        ip_str = str(ip)
        
        # DNS-based blocklists
        dns_blocklists = [
            ('zen.spamhaus.org', 'Spamhaus ZEN'),
            ('bl.spamcop.net', 'SpamCop'),
            ('dnsbl.sorbs.net', 'SORBS'),
            ('b.barracudacentral.org', 'Barracuda'),
            ('dnsbl-1.uceprotect.net', 'UCEPROTECT Level 1'),
            ('psbl.surriel.com', 'Passive Spam Block List'),
            ('cbl.abuseat.org', 'Composite Blocking List')
        ]
        
        for blocklist, name in dns_blocklists:
            result = self._check_dns_blocklist(ip_str, blocklist, name)
            results.append(result)
        
        # Check CrowdSec (via API if available)
        crowdsec_result = self._check_crowdsec(ip_str)
        results.append(crowdsec_result)
        
        # Additional reputation checks
        reputation_result = self._check_reputation_services(ip_str)
        results.extend(reputation_result)
        
        return results

    def _check_dns_blocklist(self, ip_str: str, blocklist: str, name: str) -> BlocklistResult:
        """Check IP against DNS-based blocklist."""
        try:
            # Reverse IP for DNS query
            if '.' in ip_str:  # IPv4
                octets = ip_str.split('.')
                reversed_ip = '.'.join(reversed(octets))
            else:  # IPv6 - simplified, would need full implementation
                return BlocklistResult(source=name, listed=False, details="IPv6 not supported")
            
            query_host = f"{reversed_ip}.{blocklist}"
            
            # Perform DNS lookup
            try:
                socket.gethostbyname(query_host)
                # If we get here, IP is listed
                return BlocklistResult(source=name, listed=True, details=f"Listed in {blocklist}")
            except socket.gaierror:
                # Not listed
                return BlocklistResult(source=name, listed=False)
                
        except Exception as e:
            return BlocklistResult(source=name, listed=False, details=f"Check failed: {str(e)}")

    def _check_crowdsec(self, ip_str: str) -> BlocklistResult:
        """Check IP against CrowdSec database."""
        try:
            # CrowdSec CTI API (requires API key for full access)
            # Using public smoke test endpoint for demonstration
            response = self.session.get(
                f"https://cti.api.crowdsec.net/v2/smoke/{ip_str}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                is_malicious = data.get('ip_range_score', 0) > 0
                details = f"Score: {data.get('ip_range_score', 0)}"
                return BlocklistResult(source="CrowdSec", listed=is_malicious, details=details)
            else:
                return BlocklistResult(source="CrowdSec", listed=False, details="API unavailable")
                
        except Exception as e:
            return BlocklistResult(source="CrowdSec", listed=False, details=f"Check failed: {str(e)}")

    def _check_reputation_services(self, ip_str: str) -> List[BlocklistResult]:
        """Check additional reputation services."""
        results = []
        
        # AbuseIPDB (requires API key for full functionality)
        try:
            # Using a simple check without API key
            response = self.session.get(
                f"https://www.abuseipdb.com/check/{ip_str}",
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; IP-ManA/1.0)'}
            )
            
            if response.status_code == 200:
                # Simple heuristic - look for indicators in response
                content = response.text.lower()
                is_reported = 'reported' in content and 'abuse' in content
                results.append(BlocklistResult(
                    source="AbuseIPDB", 
                    listed=is_reported, 
                    details="Heuristic check"
                ))
            else:
                results.append(BlocklistResult(
                    source="AbuseIPDB", 
                    listed=False, 
                    details="Service unavailable"
                ))
                
        except Exception as e:
            results.append(BlocklistResult(
                source="AbuseIPDB", 
                listed=False, 
                details=f"Check failed: {str(e)}"
            ))
        
        return results

    def _filter_blocklist_results(self, blocklist_results: List[BlocklistResult], mode: str) -> List[BlocklistResult]:
        """
        Filter blocklist results based on reporting mode.
        
        Args:
            blocklist_results: List of all blocklist check results
            mode: Reporting mode ("dense", "full", "full-err")
            
        Returns:
            Filtered list of blocklist results according to mode requirements
        """
        if mode == "dense":
            # Requirement 8.11: In dense mode, show only positive findings for blocklist checks
            return [result for result in blocklist_results if result.listed]
        else:
            # Requirement 8.12: In full mode, show all blocklist check results
            return blocklist_results

    def _calculate_reputation_score(self, blocklist_results: List[BlocklistResult]) -> Optional[float]:
        """
        Calculate reputation score based on blocklist results.
        
        Args:
            blocklist_results: List of blocklist check results
            
        Returns:
            Reputation score (0.0 = bad, 1.0 = good) or None if insufficient data
        """
        if not blocklist_results:
            return None
        
        total_checks = len(blocklist_results)
        positive_hits = sum(1 for result in blocklist_results if result.listed)
        
        # Simple scoring: 1.0 - (positive_hits / total_checks)
        score = 1.0 - (positive_hits / total_checks)
        
        return round(score, 2)

    def _extract_emails(self, whois_data: Dict) -> List[str]:
        """Extract email addresses from WHOIS data."""
        emails = []
        
        # Look for emails in various places in WHOIS data
        def extract_from_dict(data, emails_list):
            if isinstance(data, dict):
                for key, value in data.items():
                    if 'email' in key.lower() and isinstance(value, str):
                        emails_list.append(value)
                    elif isinstance(value, (dict, list)):
                        extract_from_dict(value, emails_list)
            elif isinstance(data, list):
                for item in data:
                    extract_from_dict(item, emails_list)
        
        extract_from_dict(whois_data, emails)
        
        # Remove duplicates and return
        return list(set(emails))

    def _whois_to_dict(self, whois_result: WhoisResult) -> Dict:
        """Convert WhoisResult to dictionary."""
        return {
            "network": whois_result.network,
            "country": whois_result.country,
            "org": whois_result.org,
            "description": whois_result.description,
            "emails": whois_result.emails or [],
            "created": whois_result.created,
            "updated": whois_result.updated
        }

    def _geolocation_to_dict(self, geo_result: GeolocationResult) -> Dict:
        """Convert GeolocationResult to dictionary."""
        return {
            "country": geo_result.country,
            "country_code": geo_result.country_code,
            "region": geo_result.region,
            "city": geo_result.city,
            "latitude": geo_result.latitude,
            "longitude": geo_result.longitude,
            "timezone": geo_result.timezone,
            "isp": geo_result.isp
        }

    def _asn_to_dict(self, asn_result: ASNResult) -> Dict:
        """Convert ASNResult to dictionary."""
        return {
            "asn": asn_result.asn,
            "description": asn_result.description,
            "country": asn_result.country,
            "registry": asn_result.registry
        }

    def _blocklist_to_dict(self, blocklist_result: BlocklistResult) -> Dict:
        """Convert BlocklistResult to dictionary."""
        return {
            "source": blocklist_result.source,
            "listed": blocklist_result.listed,
            "details": blocklist_result.details
        }
