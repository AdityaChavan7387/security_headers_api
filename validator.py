import ipaddress
import socket
from urllib.parse import urlparse


BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_url(url: str) -> tuple[bool, str]:
    """
    Returns (is_valid: bool, error_message: str)
    """
    if not url or not url.strip():
        return False, "url is required"

    url = url.strip()

    if len(url) > 2048:
        return False, "URL is too long"

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, "URL must use http or https"

    if not parsed.netloc:
        return False, "Invalid URL format"

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL format"

    # Block localhost by name
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        return False, "Scanning local or private network addresses is not allowed"

    # Resolve hostname and check if it resolves to a private/internal IP
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for info in resolved_ips:
            ip_str = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                for network in BLOCKED_IP_NETWORKS:
                    if ip_obj in network:
                        return False, "Scanning local or private network addresses is not allowed"
            except ValueError:
                continue
    except socket.gaierror:
        # If DNS fails during validation, let the scanner handle the unreachable error
        pass

    return True, ""