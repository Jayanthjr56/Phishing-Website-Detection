"""
Utility functions for the Phishing Detection System
"""

import re
import socket
from urllib.parse import urlparse
import hashlib


def is_valid_url(url):
    """
    Validate if a string is a valid URL
    
    Args:
        url: String to validate
    
    Returns:
        bool: True if valid URL
    """
    if not url or not isinstance(url, str):
        return False
    
    # Add scheme if missing for parsing
    test_url = url
    if not url.startswith(('http://', 'https://')):
        test_url = 'https://' + url
    
    try:
        parsed = urlparse(test_url)
        return all([parsed.scheme, parsed.netloc])
    except:
        return False


def normalize_url(url):
    """
    Normalize a URL for consistent processing
    
    Args:
        url: URL string
    
    Returns:
        str: Normalized URL
    """
    if not url:
        return url
    
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    # Lowercase scheme and netloc
    parsed = urlparse(url)
    url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
    if parsed.query:
        url += '?' + parsed.query
    if parsed.fragment:
        url += '#' + parsed.fragment
    
    return url


def extract_domain(url):
    """
    Extract the domain from a URL
    
    Args:
        url: URL string
    
    Returns:
        str: Domain name
    """
    if not url:
        return ''
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return ''


def get_url_hash(url):
    """
    Get a hash of a URL for caching/comparison
    
    Args:
        url: URL string
    
    Returns:
        str: SHA256 hash of normalized URL
    """
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def resolve_domain(domain, timeout=5):
    """
    Resolve a domain to IP addresses
    
    Args:
        domain: Domain name
        timeout: Socket timeout in seconds
    
    Returns:
        list: List of IP addresses or empty list on failure
    """
    try:
        socket.setdefaulttimeout(timeout)
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except:
        return []


def is_ip_address(string):
    """
    Check if a string is an IP address
    
    Args:
        string: String to check
    
    Returns:
        bool: True if IP address
    """
    # IPv4
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_pattern.match(string):
        parts = string.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True
    
    # IPv6 (simplified check)
    if ':' in string and not '/' in string:
        try:
            socket.inet_pton(socket.AF_INET6, string)
            return True
        except:
            pass
    
    return False


def sanitize_url_for_display(url, max_length=100):
    """
    Sanitize a URL for safe display
    
    Args:
        url: URL string
        max_length: Maximum display length
    
    Returns:
        str: Sanitized URL
    """
    if not url:
        return ''
    
    # Remove potentially dangerous characters
    url = url.replace('<', '&lt;').replace('>', '&gt;')
    url = url.replace('"', '&quot;').replace("'", '&#39;')
    
    # Truncate if too long
    if len(url) > max_length:
        url = url[:max_length-3] + '...'
    
    return url


def calculate_similarity(str1, str2):
    """
    Calculate similarity between two strings using Levenshtein distance
    
    Args:
        str1: First string
        str2: Second string
    
    Returns:
        float: Similarity score (0.0 to 1.0)
    """
    if not str1 or not str2:
        return 0.0
    
    len1, len2 = len(str1), len(str2)
    
    if len1 == 0 or len2 == 0:
        return 0.0
    
    # Create distance matrix
    matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    
    for i in range(len1 + 1):
        matrix[i][0] = i
    for j in range(len2 + 1):
        matrix[0][j] = j
    
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if str1[i-1] == str2[j-1] else 1
            matrix[i][j] = min(
                matrix[i-1][j] + 1,      # deletion
                matrix[i][j-1] + 1,      # insertion
                matrix[i-1][j-1] + cost  # substitution
            )
    
    distance = matrix[len1][len2]
    max_len = max(len1, len2)
    
    return 1.0 - (distance / max_len)


def batch_urls(urls, batch_size=100):
    """
    Split URLs into batches
    
    Args:
        urls: List of URLs
        batch_size: Maximum batch size
    
    Yields:
        list: Batches of URLs
    """
    for i in range(0, len(urls), batch_size):
        yield urls[i:i + batch_size]


class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    def is_allowed(self, key):
        """Check if a request is allowed"""
        import time
        current_time = time.time()
        
        # Clean old entries
        cutoff = current_time - self.window_seconds
        self.requests = {k: v for k, v in self.requests.items() 
                        if v[-1] > cutoff}
        
        # Check and update
        if key not in self.requests:
            self.requests[key] = [current_time]
            return True
        
        # Filter to window
        self.requests[key] = [t for t in self.requests[key] 
                             if t > cutoff]
        
        if len(self.requests[key]) < self.max_requests:
            self.requests[key].append(current_time)
            return True
        
        return False
