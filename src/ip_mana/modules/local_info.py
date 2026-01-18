"""
Local Information Module (Module 2) for gathering local network intelligence.
"""

import socket
import subprocess
import platform
import re
import logging
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_interface
from typing import Dict, List, Optional, Union, Any
import nmap
import netifaces

# Type alias for IP addresses
IPAddress = Union[IPv4Address, IPv6Address]

logger = logging.getLogger(__name__)


@dataclass
class MACAddress:
    """MAC address with vendor information."""
    address: str
    vendor: Optional[str] = None
    is_gateway: bool = False


@dataclass
class ReachabilityResult:
    """Result of reachability testing."""
    reachable: bool
    response_time: Optional[float] = None
    error: Optional[str] = None


@dataclass
class NmapResult:
    """Result of nmap scanning."""
    host_up: bool
    os_detection: Dict[str, Any]
    open_ports: List[Dict[str, Any]]
    services: Dict[int, Dict[str, str]]


@dataclass
class SSLResult:
    """Result of SSL/TLS analysis."""
    port: int
    protocol: str
    certificate: Optional[Dict[str, Any]] = None
    cipher_suites: List[str] = None
    vulnerabilities: List[str] = None


@dataclass
class TracerouteResult:
    """Result of traceroute analysis."""
    method: str
    hops: List[Dict[str, Any]]
    success: bool
    error: Optional[str] = None


@dataclass
class LocalInfoResult:
    """Complete local information analysis result."""
    is_local_subnet: bool
    reachable: bool
    mac_address: Optional[MACAddress]
    nmap_results: NmapResult
    ssl_results: List[SSLResult]
    traceroute_results: List[TracerouteResult]
    reverse_dns: Optional[str] = None


class LocalInfoModule:
    """Module for gathering information from the local network environment."""

    def __init__(self):
        """Initialize the local info module."""
        self.nm = nmap.PortScanner()
        self._mac_vendor_cache = {}

    def analyze(self, ip: IPAddress) -> LocalInfoResult:
        """
        Perform comprehensive local network analysis.

        Args:
            ip: IPAddress object to analyze

        Returns:
            LocalInfoResult containing all local analysis results
        """
        logger.info(f"Starting local analysis for {ip}")

        # Check if IP is in local subnet
        is_local = self._is_local_subnet(ip)

        # Test reachability
        reachability = self.check_reachability(ip)

        # Get MAC address if reachable and local
        mac_address = None
        if reachability.reachable and is_local:
            mac_address = self.get_mac_address(ip)

        # Perform nmap scan
        nmap_results = self.perform_nmap_scan(ip)

        # Perform traceroute
        traceroute_results = self._perform_traceroute(ip)

        # Perform reverse DNS lookup
        reverse_dns = self._reverse_dns_lookup(ip)

        # Analyze SSL services if web/mail ports are found
        ssl_results = []
        if nmap_results.open_ports:
            ssl_ports = self._identify_ssl_ports(nmap_results.open_ports)
            if ssl_ports:
                ssl_results = self.analyze_ssl_services(ip, ssl_ports)

        return LocalInfoResult(
            is_local_subnet=is_local,
            reachable=reachability.reachable,
            mac_address=mac_address,
            nmap_results=nmap_results,
            ssl_results=ssl_results,
            traceroute_results=traceroute_results,
            reverse_dns=reverse_dns
        )

    def _is_local_subnet(self, ip: IPAddress) -> bool:
        """
        Determine if IP address is part of local machine's subnet.

        Args:
            ip: IP address to check

        Returns:
            True if IP is in local subnet, False otherwise
        """
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)

                # Check IPv4 addresses
                if netifaces.AF_INET in addrs and isinstance(ip, IPv4Address):
                    for addr_info in addrs[netifaces.AF_INET]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            try:
                                local_net = ip_interface(
                                    f"{addr_info['addr']}/{addr_info['netmask']}")
                                if ip in local_net.network:
                                    return True
                            except Exception:
                                continue

                # Check IPv6 addresses
                if netifaces.AF_INET6 in addrs and isinstance(ip, IPv6Address):
                    for addr_info in addrs[netifaces.AF_INET6]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            try:
                                # IPv6 netmask is often given as prefix length
                                addr = addr_info['addr'].split(
                                    '%')[0]  # Remove zone identifier
                                local_net = ip_interface(
                                    f"{addr}/{addr_info['netmask']}")
                                if ip in local_net.network:
                                    return True
                            except Exception:
                                continue

            return False
        except Exception as e:
            logger.warning(f"Error checking local subnet for {ip}: {e}")
            return False

    def check_reachability(self, ip: IPAddress) -> ReachabilityResult:
        """
        Test IP address reachability via ping.

        Args:
            ip: IP address to test

        Returns:
            ReachabilityResult with ping results
        """
        try:
            # Determine ping command based on OS and IP version
            system = platform.system().lower()
            ip_str = str(ip)

            if system == "windows":
                cmd = ["ping", "-n", "1", ip_str]
            else:
                if isinstance(ip, IPv6Address):
                    cmd = ["ping6", "-c", "1", ip_str]
                else:
                    cmd = ["ping", "-c", "1", ip_str]

            # Execute ping
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                # Extract response time from output
                response_time = self._extract_ping_time(result.stdout)
                return ReachabilityResult(reachable=True, response_time=response_time)
            else:
                return ReachabilityResult(reachable=False, error=result.stderr.strip())

        except subprocess.TimeoutExpired:
            return ReachabilityResult(reachable=False, error="Ping timeout")
        except Exception as e:
            return ReachabilityResult(reachable=False, error=str(e))

    def _extract_ping_time(self, ping_output: str) -> Optional[float]:
        """Extract response time from ping output."""
        try:
            # Look for time patterns in ping output
            time_patterns = [
                r'time[<=](\d+\.?\d*)\s*ms',
                r'time=(\d+\.?\d*)\s*ms',
                r'(\d+\.?\d*)\s*ms'
            ]

            for pattern in time_patterns:
                match = re.search(pattern, ping_output, re.IGNORECASE)
                if match:
                    return float(match.group(1))
            return None
        except Exception:
            return None

    def get_mac_address(self, ip: IPAddress) -> Optional[MACAddress]:
        """
        Discover associated MAC address when available.

        Args:
            ip: IP address to lookup

        Returns:
            MACAddress object with vendor info, or None if not found
        """
        try:
            # Try ARP table lookup first
            mac = self._get_mac_from_arp(ip)

            if mac:
                vendor = self._get_mac_vendor(mac)
                is_gateway = self._is_gateway_mac(ip, mac)
                return MACAddress(address=mac, vendor=vendor, is_gateway=is_gateway)

            return None
        except Exception as e:
            logger.warning(f"Error getting MAC address for {ip}: {e}")
            return None

    def _get_mac_from_arp(self, ip: IPAddress) -> Optional[str]:
        """Get MAC address from ARP table."""
        try:
            system = platform.system().lower()
            ip_str = str(ip)

            if system == "windows":
                cmd = ["arp", "-a", ip_str]
            else:
                cmd = ["arp", "-n", ip_str]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                # Parse MAC address from output
                mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
                match = re.search(mac_pattern, result.stdout)
                if match:
                    return match.group(0).lower().replace('-', ':')

            return None
        except Exception:
            return None

    def _get_mac_vendor(self, mac: str) -> Optional[str]:
        """Get vendor information from MAC address OUI."""
        try:
            # Extract OUI (first 3 octets)
            oui = mac[:8].replace(':', '').upper()

            # Check cache first
            if oui in self._mac_vendor_cache:
                return self._mac_vendor_cache[oui]

            # Simple vendor lookup (in real implementation, use OUI database)
            vendor_map = {
                '00:50:56': 'VMware',
                '08:00:27': 'VirtualBox',
                '52:54:00': 'QEMU/KVM',
                '00:0C:29': 'VMware',
                '00:1C:42': 'Parallels',
            }

            vendor = vendor_map.get(oui[:8])
            self._mac_vendor_cache[oui] = vendor
            return vendor

        except Exception:
            return None

    def _is_gateway_mac(self, ip: IPAddress, mac: str) -> bool:
        """Determine if MAC address belongs to gateway/router."""
        try:
            # Get default gateway MAC addresses
            gateways = netifaces.gateways()
            default_gw = gateways.get('default', {})

            for family, (gw_ip, interface) in default_gw.items():
                if gw_ip == str(ip):
                    return True

            return False
        except Exception:
            return False

    def perform_nmap_scan(self, ip: IPAddress) -> NmapResult:
        """
        Execute nmap discovery, OS detection, and port scan.

        Args:
            ip: IP address to scan

        Returns:
            NmapResult with scan findings
        """
        try:
            ip_str = str(ip)

            # Perform comprehensive scan
            # -sS: SYN scan, -O: OS detection, -sV: Service version detection
            # -p-: All ports (can be limited for performance)
            scan_args = f"-sS -O -sV -p 1-1000 {ip_str}"

            logger.info(f"Starting nmap scan: {scan_args}")
            self.nm.scan(hosts=ip_str, arguments=scan_args)

            if ip_str not in self.nm.all_hosts():
                return NmapResult(
                    host_up=False,
                    os_detection={},
                    open_ports=[],
                    services={}
                )

            host_info = self.nm[ip_str]

            # Extract OS detection info
            os_detection = {}
            if 'osmatch' in host_info:
                os_detection = {
                    'matches': host_info['osmatch'],
                    'fingerprint': host_info.get('osfingerprint', [])
                }

            # Extract open ports and services
            open_ports = []
            services = {}

            for protocol in host_info.all_protocols():
                ports = host_info[protocol].keys()
                for port in ports:
                    port_info = host_info[protocol][port]
                    if port_info['state'] == 'open':
                        port_data = {
                            'port': port,
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                        open_ports.append(port_data)
                        services[port] = {
                            'name': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }

            return NmapResult(
                host_up=True,
                os_detection=os_detection,
                open_ports=open_ports,
                services=services
            )

        except Exception as e:
            logger.error(f"Nmap scan failed for {ip}: {e}")
            return NmapResult(
                host_up=False,
                os_detection={},
                open_ports=[],
                services={}
            )

    def _identify_ssl_ports(self, open_ports: List[Dict[str, Any]]) -> List[int]:
        """Identify ports that should be tested for SSL/TLS."""
        ssl_ports = []
        common_ssl_ports = {443, 993, 995, 465, 587, 636, 989, 990, 992, 993, 995}

        for port_info in open_ports:
            port = port_info['port']
            service = port_info.get('service', '').lower()

            # Check if it's a known SSL port
            if port in common_ssl_ports:
                ssl_ports.append(port)
            # Check if service name indicates SSL
            elif 'ssl' in service or 'tls' in service or 'https' in service:
                ssl_ports.append(port)
            # Check for web servers on non-standard ports
            elif service in ['http', 'www'] and port != 80:
                ssl_ports.append(port)

        return ssl_ports

    def analyze_ssl_services(self, ip: IPAddress, ports: List[int]) -> List[SSLResult]:
        """
        Analyze SSL/TLS services using sslyze with comprehensive vulnerability detection
        and certificate deduplication.

        Args:
            ip: IP address to analyze
            ports: List of ports to test for SSL

        Returns:
            List of SSLResult objects with deduplicated certificates
        """
        ssl_results = []

        try:
            # Import sslyze components
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
            from sslyze.plugins.scan_commands import ScanCommand

            # Comprehensive scan commands for vulnerability detection
            scan_commands = {
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.SESSION_RENEGOTIATION,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.EARLY_DATA
            }

            # Create scan requests for all ports
            scan_requests = []
            for port in ports:
                try:
                    server_location = ServerNetworkLocation(str(ip), port)
                    scan_request = ServerScanRequest(
                        server_location=server_location,
                        scan_commands=scan_commands
                    )
                    scan_requests.append(scan_request)
                except Exception as e:
                    logger.warning(
                        f"Failed to create scan request for {ip}:{port}: {e}")
                    ssl_results.append(SSLResult(
                        port=port,
                        protocol='TLS',
                        vulnerabilities=[f"Scan setup failed: {str(e)}"]
                    ))

            if scan_requests:
                # Perform scans
                scanner = Scanner()
                scanner.queue_scans(scan_requests)

                # Process results
                raw_results = {}
                for result in scanner.get_results():
                    port = result.server_location.port
                    raw_results[port] = result

                    ssl_result = SSLResult(
                        port=port,
                        protocol='TLS',
                        certificate=self._extract_certificate_info(result),
                        cipher_suites=self._extract_cipher_suites(result),
                        vulnerabilities=self._extract_comprehensive_vulnerabilities(result))
                    ssl_results.append(ssl_result)

                # Apply certificate deduplication
                ssl_results = self._deduplicate_certificates(ssl_results)

        except ImportError:
            logger.warning("sslyze not available, skipping SSL analysis")
        except Exception as e:
            logger.error(f"SSL analysis error: {e}")
            # Add error results for all requested ports
            for port in ports:
                ssl_results.append(SSLResult(
                    port=port,
                    protocol='TLS',
                    vulnerabilities=[f"SSL analysis failed: {str(e)}"]
                ))

        return ssl_results

    def _extract_certificate_info(self, scan_result) -> Optional[Dict[str, Any]]:
        """Extract certificate information from sslyze result."""
        try:
            cert_info = scan_result.scan_result.certificate_info
            if cert_info and cert_info.certificate_deployments:
                cert = cert_info.certificate_deployments[0].received_certificate_chain[0]
                return {
                    'subject': str(cert.subject),
                    'issuer': str(cert.issuer),
                    'serial_number': str(cert.serial_number),
                    'not_valid_before': cert.not_valid_before.isoformat(),
                    'not_valid_after': cert.not_valid_after.isoformat(),
                }
        except Exception:
            pass
        return None

    def _extract_cipher_suites(self, scan_result) -> List[str]:
        """Extract cipher suites from sslyze result across all TLS versions."""
        cipher_suites = []

        try:
            # Extract cipher suites from all TLS versions
            tls_versions = [
                'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites',
                'tls_1_0_cipher_suites', 'tls_1_1_cipher_suites',
                'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites'
            ]

            for version in tls_versions:
                if hasattr(scan_result.scan_result, version):
                    cipher_result = getattr(scan_result.scan_result, version)
                    if cipher_result and hasattr(
                            cipher_result, 'accepted_cipher_suites'):
                        for cipher in cipher_result.accepted_cipher_suites:
                            cipher_name = f"{
                                version.replace(
                                    '_cipher_suites', '').upper()}: {
                                cipher.cipher_suite.name}"
                            cipher_suites.append(cipher_name)

        except Exception as e:
            logger.warning(f"Error extracting cipher suites: {e}")

        return cipher_suites

    def _deduplicate_certificates(
            self, ssl_results: List[SSLResult]) -> List[SSLResult]:
        """
        Deduplicate identical certificates across multiple ports.

        When identical certificates are found, they are reported once with
        port-specific differences clearly documented.

        Args:
            ssl_results: List of SSL results to deduplicate

        Returns:
            List of SSL results with deduplicated certificates
        """
        if not ssl_results:
            return ssl_results

        # Group results by certificate identity
        cert_groups = {}
        results_without_certs = []

        for result in ssl_results:
            if result.certificate:
                cert_identity = self._get_certificate_identity(result.certificate)
                if cert_identity not in cert_groups:
                    cert_groups[cert_identity] = []
                cert_groups[cert_identity].append(result)
            else:
                # Keep results without certificates as-is
                results_without_certs.append(result)

        # Process certificate groups
        deduplicated_results = []

        for cert_identity, group_results in cert_groups.items():
            if len(group_results) == 1:
                # Single occurrence, keep as-is
                deduplicated_results.extend(group_results)
            else:
                # Multiple occurrences of same certificate - deduplicate
                primary_result = group_results[0]
                other_ports = [r.port for r in group_results[1:]]

                # Combine port information and differences
                all_ports = [r.port for r in group_results]
                port_differences = self._document_port_differences(group_results)

                # Create deduplicated result with port information
                deduplicated_result = SSLResult(
                    port=primary_result.port,  # Primary port
                    protocol=primary_result.protocol,
                    certificate=primary_result.certificate.copy() if primary_result.certificate else None,
                    cipher_suites=primary_result.cipher_suites.copy() if primary_result.cipher_suites else [],
                    vulnerabilities=primary_result.vulnerabilities.copy() if primary_result.vulnerabilities else []
                )

                # Add port information to certificate
                if deduplicated_result.certificate:
                    deduplicated_result.certificate['shared_across_ports'] = sorted(
                        all_ports)
                    deduplicated_result.certificate['port_differences'] = port_differences

                # Merge vulnerabilities from all ports
                all_vulnerabilities = set()
                for result in group_results:
                    if result.vulnerabilities:
                        all_vulnerabilities.update(result.vulnerabilities)
                deduplicated_result.vulnerabilities = list(all_vulnerabilities)

                # Merge cipher suites from all ports
                all_cipher_suites = set()
                for result in group_results:
                    if result.cipher_suites:
                        all_cipher_suites.update(result.cipher_suites)
                deduplicated_result.cipher_suites = list(all_cipher_suites)

                deduplicated_results.append(deduplicated_result)

                # Add additional results for other ports with reference to primary
                for other_result in group_results[1:]:
                    reference_result = SSLResult(
                        port=other_result.port,
                        protocol=other_result.protocol,
                        certificate={
                            'reference_to_port': primary_result.port,
                            'note': 'Identical certificate - see primary port for details'},
                        cipher_suites=other_result.cipher_suites,
                        vulnerabilities=other_result.vulnerabilities)
                    deduplicated_results.append(reference_result)

        # Add results without certificates
        deduplicated_results.extend(results_without_certs)

        # Sort by port for consistent output
        deduplicated_results.sort(key=lambda x: x.port)

        return deduplicated_results

    def _get_certificate_identity(self, certificate: Dict[str, Any]) -> str:
        """
        Get a unique identity for a certificate based on key fields.

        Args:
            certificate: Certificate information dictionary

        Returns:
            Unique string identifying the certificate
        """
        subject = certificate.get('subject', '')
        serial_number = certificate.get('serial_number', '')
        issuer = certificate.get('issuer', '')

        # Create a unique identifier from key certificate fields
        return f"{subject}|{serial_number}|{issuer}"

    def _document_port_differences(
            self, group_results: List[SSLResult]) -> Dict[int, Dict[str, Any]]:
        """
        Document differences between ports that share the same certificate.

        Args:
            group_results: List of SSL results with the same certificate

        Returns:
            Dictionary mapping port numbers to their specific differences
        """
        port_differences = {}

        for result in group_results:
            differences = {}

            # Document cipher suite differences
            if result.cipher_suites:
                differences['cipher_suites'] = result.cipher_suites

            # Document vulnerability differences
            if result.vulnerabilities:
                differences['vulnerabilities'] = result.vulnerabilities

            # Document protocol differences if any
            differences['protocol'] = result.protocol

            port_differences[result.port] = differences

        return port_differences

    def _extract_comprehensive_vulnerabilities(self, scan_result) -> List[str]:
        """Extract comprehensive vulnerabilities from sslyze result."""
        vulnerabilities = []

        try:
            # Check for SSL 2.0 (deprecated and insecure)
            if hasattr(scan_result.scan_result, 'ssl_2_0_cipher_suites'):
                ssl2_result = scan_result.scan_result.ssl_2_0_cipher_suites
                if ssl2_result and ssl2_result.accepted_cipher_suites:
                    vulnerabilities.append("SSL 2.0 enabled (CRITICAL)")

            # Check for SSL 3.0 (deprecated due to POODLE)
            if hasattr(scan_result.scan_result, 'ssl_3_0_cipher_suites'):
                ssl3_result = scan_result.scan_result.ssl_3_0_cipher_suites
                if ssl3_result and ssl3_result.accepted_cipher_suites:
                    vulnerabilities.append(
                        "SSL 3.0 enabled (HIGH - POODLE vulnerability)")

            # Check for weak TLS versions
            if hasattr(scan_result.scan_result, 'tls_1_0_cipher_suites'):
                tls10_result = scan_result.scan_result.tls_1_0_cipher_suites
                if tls10_result and tls10_result.accepted_cipher_suites:
                    vulnerabilities.append("TLS 1.0 enabled (MEDIUM - deprecated)")

            if hasattr(scan_result.scan_result, 'tls_1_1_cipher_suites'):
                tls11_result = scan_result.scan_result.tls_1_1_cipher_suites
                if tls11_result and tls11_result.accepted_cipher_suites:
                    vulnerabilities.append("TLS 1.1 enabled (MEDIUM - deprecated)")

            # Check for Heartbleed vulnerability
            if hasattr(scan_result.scan_result, 'heartbleed'):
                heartbleed_result = scan_result.scan_result.heartbleed
                if heartbleed_result and heartbleed_result.is_vulnerable_to_heartbleed:
                    vulnerabilities.append("Heartbleed vulnerability (CRITICAL)")

            # Check for OpenSSL CCS Injection
            if hasattr(scan_result.scan_result, 'openssl_ccs_injection'):
                ccs_result = scan_result.scan_result.openssl_ccs_injection
                if ccs_result and ccs_result.is_vulnerable_to_ccs_injection:
                    vulnerabilities.append("OpenSSL CCS Injection vulnerability (HIGH)")

            # Check for TLS compression (CRIME attack)
            if hasattr(scan_result.scan_result, 'tls_compression'):
                compression_result = scan_result.scan_result.tls_compression
                if compression_result and compression_result.supports_compression:
                    vulnerabilities.append(
                        "TLS compression enabled (MEDIUM - CRIME attack)")

            # Check for insecure renegotiation
            if hasattr(scan_result.scan_result, 'session_renegotiation'):
                renegotiation_result = scan_result.scan_result.session_renegotiation
                if renegotiation_result:
                    if not renegotiation_result.supports_secure_renegotiation:
                        vulnerabilities.append("Insecure renegotiation (MEDIUM)")
                    if renegotiation_result.is_vulnerable_to_client_renegotiation_dos:
                        vulnerabilities.append(
                            "Client renegotiation DoS vulnerability (MEDIUM)")

            # Check for weak cipher suites
            weak_ciphers = self._check_weak_cipher_suites(scan_result)
            vulnerabilities.extend(weak_ciphers)

            # Check certificate issues
            cert_issues = self._check_certificate_issues(scan_result)
            vulnerabilities.extend(cert_issues)

        except Exception as e:
            logger.warning(f"Error extracting vulnerabilities: {e}")
            vulnerabilities.append(f"Vulnerability analysis error: {str(e)}")

        return vulnerabilities

    def _check_weak_cipher_suites(self, scan_result) -> List[str]:
        """Check for weak cipher suites across all TLS versions."""
        weak_ciphers = []

        # Define patterns for weak ciphers
        weak_patterns = [
            'NULL', 'EXPORT', 'DES', '3DES', 'RC4', 'MD5', 'SHA1'
        ]

        # Check all TLS versions for weak ciphers
        tls_versions = [
            'tls_1_0_cipher_suites', 'tls_1_1_cipher_suites',
            'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites'
        ]

        for version in tls_versions:
            if hasattr(scan_result.scan_result, version):
                cipher_result = getattr(scan_result.scan_result, version)
                if cipher_result and cipher_result.accepted_cipher_suites:
                    for cipher in cipher_result.accepted_cipher_suites:
                        cipher_name = cipher.cipher_suite.name
                        for weak_pattern in weak_patterns:
                            if weak_pattern in cipher_name.upper():
                                severity = "HIGH" if weak_pattern in [
                                    'NULL', 'EXPORT', 'DES'] else "MEDIUM"
                                weak_ciphers.append(
                                    f"Weak cipher {cipher_name} ({severity})")
                                break

        return weak_ciphers

    def _check_certificate_issues(self, scan_result) -> List[str]:
        """Check for certificate-related security issues."""
        cert_issues = []

        try:
            if hasattr(scan_result.scan_result, 'certificate_info'):
                cert_info = scan_result.scan_result.certificate_info
                if cert_info and cert_info.certificate_deployments:
                    deployment = cert_info.certificate_deployments[0]
                    cert = deployment.received_certificate_chain[0]

                    # Check certificate expiration
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)

                    if cert.not_valid_after < now:
                        cert_issues.append("Certificate expired (HIGH)")
                    elif (cert.not_valid_after - now).days < 30:
                        cert_issues.append("Certificate expires soon (MEDIUM)")

                    # Check for weak signature algorithm
                    if hasattr(cert, 'signature_algorithm_oid'):
                        sig_alg = str(cert.signature_algorithm_oid)
                        if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                            cert_issues.append(
                                "Weak certificate signature algorithm (MEDIUM)")

                    # Check key size
                    if hasattr(cert, 'public_key'):
                        try:
                            key = cert.public_key()
                            if hasattr(key, 'key_size'):
                                if key.key_size < 2048:
                                    cert_issues.append(
                                        f"Weak certificate key size: {
                                            key.key_size} bits (HIGH)")
                        except Exception:
                            pass

                    # Check for self-signed certificate
                    if cert.issuer == cert.subject:
                        cert_issues.append("Self-signed certificate (LOW)")

        except Exception as e:
            logger.warning(f"Error checking certificate issues: {e}")

        return cert_issues

    def _perform_traceroute(self, ip: IPAddress) -> List[TracerouteResult]:
        """
        Generate traceroute using multiple methods.

        Args:
            ip: IP address to trace

        Returns:
            List of TracerouteResult objects from different methods
        """
        results = []

        # Method 1: Traditional traceroute
        results.append(self._traceroute_traditional(ip))

        # Method 2: Ping-based traceroute
        results.append(self._traceroute_ping(ip))

        return [r for r in results if r is not None]

    def _traceroute_traditional(self, ip: IPAddress) -> Optional[TracerouteResult]:
        """Perform traditional traceroute."""
        try:
            system = platform.system().lower()
            ip_str = str(ip)

            if system == "windows":
                cmd = ["tracert", "-h", "10", ip_str]
            else:
                if isinstance(ip, IPv6Address):
                    cmd = ["traceroute6", "-m", "10", ip_str]
                else:
                    cmd = ["traceroute", "-m", "10", ip_str]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                hops = self._parse_traceroute_output(result.stdout)
                return TracerouteResult(
                    method="traditional",
                    hops=hops,
                    success=True
                )
            else:
                return TracerouteResult(
                    method="traditional",
                    hops=[],
                    success=False,
                    error=result.stderr.strip()
                )

        except subprocess.TimeoutExpired:
            return TracerouteResult(
                method="traditional",
                hops=[],
                success=False,
                error="Traceroute timeout"
            )
        except Exception as e:
            return TracerouteResult(
                method="traditional",
                hops=[],
                success=False,
                error=str(e)
            )

    def _traceroute_ping(self, ip: IPAddress) -> Optional[TracerouteResult]:
        """Perform ping-based traceroute with increasing TTL."""
        try:
            hops = []
            max_hops = 10

            for ttl in range(1, max_hops + 1):
                hop_result = self._ping_with_ttl(ip, ttl)
                hops.append(hop_result)

                # If we reached the destination, stop
                if hop_result.get('reached_destination', False):
                    break

            return TracerouteResult(
                method="ping",
                hops=hops,
                success=True
            )

        except Exception as e:
            return TracerouteResult(
                method="ping",
                hops=[],
                success=False,
                error=str(e)
            )

    def _ping_with_ttl(self, ip: IPAddress, ttl: int) -> Dict[str, Any]:
        """Ping with specific TTL value."""
        try:
            system = platform.system().lower()
            ip_str = str(ip)

            if system == "windows":
                cmd = ["ping", "-n", "1", "-i", str(ttl), ip_str]
            else:
                cmd = ["ping", "-c", "1", "-t", str(ttl), ip_str]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            # Parse the result to extract hop information
            hop_info = {
                'ttl': ttl,
                'ip': None,
                'hostname': None,
                'rtt': None,
                'reached_destination': False
            }

            if result.returncode == 0:
                hop_info['reached_destination'] = True
                hop_info['ip'] = ip_str
                rtt = self._extract_ping_time(result.stdout)
                if rtt:
                    hop_info['rtt'] = rtt

            return hop_info

        except Exception:
            return {
                'ttl': ttl,
                'ip': None,
                'hostname': None,
                'rtt': None,
                'reached_destination': False
            }

    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute output to extract hop information."""
        hops = []
        lines = output.split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('traceroute') or line.startswith('Tracing'):
                continue

            # Simple parsing - extract hop number, IP, and timing
            hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_data = hop_match.group(2)

                # Extract IP addresses and timing
                ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
                time_pattern = r'(\d+\.?\d*)\s*ms'

                ips = re.findall(ip_pattern, hop_data)
                times = re.findall(time_pattern, hop_data)

                hop_info = {
                    'hop': hop_num,
                    'ip': ips[0] if ips else None,
                    'hostname': None,
                    'rtt': float(times[0]) if times else None
                }
                hops.append(hop_info)

        return hops

    def _reverse_dns_lookup(self, ip: IPAddress) -> Optional[str]:
        """
        Perform reverse DNS lookup against local resolver.

        Args:
            ip: IP address to lookup

        Returns:
            Hostname if found, None otherwise
        """
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except Exception:
            return None
