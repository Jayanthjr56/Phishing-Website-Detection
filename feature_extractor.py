"""
Feature Extractor Module - ORIGINAL CUSTOM FEATURES
Extracts unique features from URLs for phishing detection
These features are designed specifically for this project and not copied from any source
"""

import re
import math
import string
import socket
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter
import tldextract
import dns.resolver
import ssl
import datetime
import hashlib
import config

class FeatureExtractor:
    """
    Extracts custom features from URLs for phishing detection.
    Features are designed based on analysis of phishing patterns but
    are original implementations not copied from existing repositories.
    """
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = config.DNS_TIMEOUT
        self.dns_resolver.lifetime = config.DNS_TIMEOUT
        
    def extract_all_features(self, url):
        """
        Extract all features from a URL
        Returns a dictionary of feature names and values
        """
        features = {}
        
        try:
            # Parse URL components
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # 1. Structural Features
            features.update(self._extract_structural_features(url, parsed, extracted))
            
            # 2. Lexical Entropy Features
            features.update(self._extract_entropy_features(url, parsed, extracted))
            
            # 3. Character Distribution Features
            features.update(self._extract_char_distribution_features(url, parsed))
            
            # 4. Brand Impersonation Features
            features.update(self._extract_brand_features(url, parsed, extracted))
            
            # 5. Suspicious Pattern Features
            features.update(self._extract_pattern_features(url, parsed))
            
            # 6. Domain Reputation Features
            features.update(self._extract_domain_features(extracted))
            
            # 7. Path Analysis Features
            features.update(self._extract_path_features(parsed))
            
            # 8. Query String Features
            features.update(self._extract_query_features(parsed))
            
            # 9. Obfuscation Detection Features
            features.update(self._extract_obfuscation_features(url, parsed))
            
            # 10. Homograph Attack Features
            features.update(self._extract_homograph_features(url, extracted))
            
            # 11. Timing and Freshness Features (static approximations)
            features.update(self._extract_timing_features(extracted))
            
            # 12. Network-based Features (DNS lookups)
            features.update(self._extract_network_features(extracted))
            
        except Exception as e:
            # Return default features if extraction fails
            features = self._get_default_features()
            features['extraction_error'] = 1
            
        return features
    
    def _extract_structural_features(self, url, parsed, extracted):
        """
        Feature Group 1: URL Structural Analysis
        Analyzes the basic structure of the URL
        """
        features = {}
        
        # Total URL length
        features['url_length'] = len(url)
        
        # Domain length
        domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        features['domain_length'] = len(domain)
        
        # Subdomain analysis
        features['subdomain_length'] = len(extracted.subdomain) if extracted.subdomain else 0
        features['subdomain_count'] = extracted.subdomain.count('.') + 1 if extracted.subdomain else 0
        
        # Path depth (number of directory levels)
        path = parsed.path
        features['path_depth'] = path.count('/') - 1 if path else 0
        features['path_length'] = len(path) if path else 0
        
        # Query string presence and complexity
        features['has_query'] = 1 if parsed.query else 0
        features['query_length'] = len(parsed.query) if parsed.query else 0
        features['query_param_count'] = len(parse_qs(parsed.query)) if parsed.query else 0
        
        # Fragment presence
        features['has_fragment'] = 1 if parsed.fragment else 0
        
        # Port analysis
        features['has_non_standard_port'] = 1 if parsed.port and parsed.port not in [80, 443] else 0
        
        # Protocol analysis
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        features['is_http'] = 1 if parsed.scheme == 'http' else 0
        
        # URL contains IP address instead of domain
        features['has_ip_address'] = 1 if self._contains_ip_address(parsed.netloc) else 0
        
        # Ratio of path to domain length
        features['path_domain_ratio'] = features['path_length'] / (features['domain_length'] + 1)
        
        # Average segment length in path
        segments = [s for s in path.split('/') if s]
        features['avg_path_segment_length'] = sum(len(s) for s in segments) / len(segments) if segments else 0
        features['max_path_segment_length'] = max(len(s) for s in segments) if segments else 0
        
        return features
    
    def _extract_entropy_features(self, url, parsed, extracted):
        """
        Feature Group 2: Information Entropy Analysis
        Measures randomness in different URL components
        """
        features = {}
        
        # Shannon entropy of full URL
        features['url_entropy'] = self._calculate_shannon_entropy(url)
        
        # Entropy of domain
        domain = extracted.domain
        features['domain_entropy'] = self._calculate_shannon_entropy(domain)
        
        # Entropy of subdomain
        features['subdomain_entropy'] = self._calculate_shannon_entropy(extracted.subdomain) if extracted.subdomain else 0
        
        # Entropy of path
        features['path_entropy'] = self._calculate_shannon_entropy(parsed.path) if parsed.path else 0
        
        # Entropy of query string
        features['query_entropy'] = self._calculate_shannon_entropy(parsed.query) if parsed.query else 0
        
        # Normalized entropy (entropy / log2(length))
        features['url_normalized_entropy'] = features['url_entropy'] / math.log2(len(url)) if len(url) > 1 else 0
        
        # Entropy difference between domain and path
        features['domain_path_entropy_diff'] = abs(features['domain_entropy'] - features['path_entropy'])
        
        # High entropy segments count (potential base64 or random strings)
        segments = [s for s in url.split('/') if s]
        high_entropy_count = sum(1 for s in segments if self._calculate_shannon_entropy(s) > 3.5)
        features['high_entropy_segments'] = high_entropy_count
        
        return features
    
    def _extract_char_distribution_features(self, url, parsed):
        """
        Feature Group 3: Character Distribution Analysis
        Analyzes the distribution and patterns of characters
        """
        features = {}
        
        # Count special characters
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['at_symbol_count'] = url.count('@')
        features['ampersand_count'] = url.count('&')
        features['equals_count'] = url.count('=')
        features['question_count'] = url.count('?')
        features['percent_count'] = url.count('%')
        features['tilde_count'] = url.count('~')
        
        # Digit analysis
        digits = sum(c.isdigit() for c in url)
        features['digit_count'] = digits
        features['digit_ratio'] = digits / len(url) if url else 0
        
        # Letter analysis
        letters = sum(c.isalpha() for c in url)
        features['letter_count'] = letters
        features['letter_ratio'] = letters / len(url) if url else 0
        
        # Uppercase ratio (excluding scheme)
        url_no_scheme = url.replace(parsed.scheme + '://', '')
        uppercase = sum(c.isupper() for c in url_no_scheme)
        features['uppercase_count'] = uppercase
        features['uppercase_ratio'] = uppercase / len(url_no_scheme) if url_no_scheme else 0
        
        # Special character ratio
        special = sum(not c.isalnum() for c in url)
        features['special_char_count'] = special
        features['special_char_ratio'] = special / len(url) if url else 0
        
        # Consecutive character patterns
        features['max_consecutive_digits'] = self._max_consecutive_chars(url, str.isdigit)
        features['max_consecutive_letters'] = self._max_consecutive_chars(url, str.isalpha)
        features['max_consecutive_consonants'] = self._max_consecutive_consonants(url)
        
        # Vowel to consonant ratio in domain
        domain = parsed.netloc
        vowels = sum(1 for c in domain.lower() if c in 'aeiou')
        consonants = sum(1 for c in domain.lower() if c.isalpha() and c not in 'aeiou')
        features['vowel_consonant_ratio'] = vowels / (consonants + 1)
        
        # Character diversity (unique chars / total chars)
        features['char_diversity'] = len(set(url)) / len(url) if url else 0
        
        return features
    
    def _extract_brand_features(self, url, parsed, extracted):
        """
        Feature Group 4: Brand Impersonation Detection
        Detects attempts to impersonate legitimate brands
        """
        features = {}
        
        url_lower = url.lower()
        domain_lower = extracted.domain.lower() if extracted.domain else ''
        subdomain_lower = extracted.subdomain.lower() if extracted.subdomain else ''
        path_lower = parsed.path.lower() if parsed.path else ''
        
        # Check for brand names in different URL parts
        brand_in_domain = 0
        brand_in_subdomain = 0
        brand_in_path = 0
        brand_count = 0
        matched_brands = []
        
        for brand in config.TARGETED_BRANDS:
            if brand in domain_lower:
                brand_in_domain = 1
                brand_count += 1
                matched_brands.append(brand)
            if brand in subdomain_lower:
                brand_in_subdomain = 1
                brand_count += 1
                matched_brands.append(brand)
            if brand in path_lower:
                brand_in_path = 1
                brand_count += 1
                matched_brands.append(brand)
        
        features['brand_in_domain'] = brand_in_domain
        features['brand_in_subdomain'] = brand_in_subdomain
        features['brand_in_path'] = brand_in_path
        features['brand_total_count'] = brand_count
        
        # Brand with typos detection (Levenshtein-based)
        features['brand_typosquat_score'] = self._detect_typosquatting(domain_lower)
        
        # Brand followed by suspicious suffix
        features['brand_with_suspicious_suffix'] = self._has_brand_suspicious_suffix(domain_lower)
        
        # Multiple brands in URL (suspicious)
        features['multiple_brands'] = 1 if len(set(matched_brands)) > 1 else 0
        
        return features
    
    def _extract_pattern_features(self, url, parsed):
        """
        Feature Group 5: Suspicious Pattern Detection
        Identifies common phishing patterns
        """
        features = {}
        
        url_lower = url.lower()
        path_lower = parsed.path.lower() if parsed.path else ''
        
        # Suspicious keywords count
        keyword_count = sum(1 for keyword in config.SUSPICIOUS_KEYWORDS if keyword in url_lower)
        features['suspicious_keyword_count'] = keyword_count
        
        # Check for double extensions (e.g., file.pdf.exe)
        features['has_double_extension'] = 1 if re.search(r'\.\w{2,4}\.\w{2,4}$', path_lower) else 0
        
        # Check for executable extensions in path
        exe_patterns = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.msi']
        features['has_executable_extension'] = 1 if any(ext in path_lower for ext in exe_patterns) else 0
        
        # Data URI detection
        features['has_data_uri'] = 1 if 'data:' in url_lower else 0
        
        # JavaScript in URL
        features['has_javascript'] = 1 if 'javascript:' in url_lower else 0
        
        # Base64 pattern detection
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        features['has_base64_pattern'] = 1 if base64_pattern.search(url) else 0
        
        # Random string detection (long alphanumeric sequences)
        random_pattern = re.compile(r'[a-z0-9]{15,}', re.IGNORECASE)
        features['has_random_string'] = 1 if random_pattern.search(url) else 0
        
        # URL shortener detection
        features['is_shortened'] = 1 if any(shortener in url_lower for shortener in config.URL_SHORTENERS) else 0
        
        # Free hosting detection
        features['uses_free_hosting'] = 1 if any(host in url_lower for host in config.FREE_HOSTING_PROVIDERS) else 0
        
        # Login/signin in subdomain (common phishing pattern)
        subdomain = parsed.netloc.split('.')[0] if '.' in parsed.netloc else ''
        features['auth_in_subdomain'] = 1 if any(kw in subdomain.lower() for kw in ['login', 'signin', 'auth', 'secure', 'account']) else 0
        
        # @ symbol in URL (can hide real domain)
        features['has_at_symbol'] = 1 if '@' in parsed.netloc else 0
        
        # Punycode detection (internationalized domain)
        features['has_punycode'] = 1 if 'xn--' in url_lower else 0
        
        # Hex encoding detection
        hex_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
        hex_matches = hex_pattern.findall(url)
        features['hex_encoded_count'] = len(hex_matches)
        features['has_excessive_encoding'] = 1 if len(hex_matches) > 5 else 0
        
        return features
    
    def _extract_domain_features(self, extracted):
        """
        Feature Group 6: Domain Reputation Analysis
        Analyzes domain-level characteristics
        """
        features = {}
        
        suffix = '.' + extracted.suffix if extracted.suffix else ''
        domain = extracted.domain
        
        # TLD analysis
        features['is_trusted_tld'] = 1 if suffix in config.TRUSTED_TLDS else 0
        features['is_suspicious_tld'] = 1 if suffix in config.SUSPICIOUS_TLDS else 0
        
        # TLD length (longer TLDs are sometimes suspicious)
        features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0
        
        # Multi-part TLD (e.g., .co.uk)
        features['is_compound_tld'] = 1 if '.' in extracted.suffix else 0
        
        # Domain is a common word (less suspicious)
        common_words = ['shop', 'store', 'buy', 'sale', 'deal', 'best', 'top', 'web', 'net', 'online']
        features['domain_is_common_word'] = 1 if domain.lower() in common_words else 0
        
        # Domain starts with suspicious prefix
        suspicious_prefixes = ['secure', 'login', 'account', 'update', 'verify', 'confirm', 'signin', 'auth']
        features['has_suspicious_prefix'] = 1 if any(domain.lower().startswith(p) for p in suspicious_prefixes) else 0
        
        # Domain ends with suspicious suffix
        suspicious_domain_suffixes = ['login', 'secure', 'verify', 'account', 'update', 'auth']
        features['has_suspicious_domain_suffix'] = 1 if any(domain.lower().endswith(s) for s in suspicious_domain_suffixes) else 0
        
        # Subdomain complexity
        subdomain = extracted.subdomain
        if subdomain:
            features['subdomain_has_hyphen'] = 1 if '-' in subdomain else 0
            features['subdomain_has_number'] = 1 if any(c.isdigit() for c in subdomain) else 0
            features['is_legitimate_subdomain'] = 1 if subdomain.lower() in config.LEGITIMATE_SUBDOMAINS else 0
        else:
            features['subdomain_has_hyphen'] = 0
            features['subdomain_has_number'] = 0
            features['is_legitimate_subdomain'] = 0
        
        # Domain contains number-letter mix (e.g., amaz0n)
        features['domain_has_digit'] = 1 if any(c.isdigit() for c in domain) else 0
        
        return features
    
    def _extract_path_features(self, parsed):
        """
        Feature Group 7: Path Analysis
        Analyzes the URL path component
        """
        features = {}
        
        path = parsed.path or ''
        path_lower = path.lower()
        
        # Common phishing path patterns
        phishing_paths = ['/.well-known/', '/wp-content/', '/wp-includes/', '/administrator/',
                         '/signin/', '/login/', '/account/', '/secure/', '/verify/', '/update/',
                         '/confirm/', '/validate/', '/authenticate/', '/webscr/', '/cmd/']
        features['has_phishing_path'] = 1 if any(p in path_lower for p in phishing_paths) else 0
        
        # File extensions in path
        features['path_has_html'] = 1 if '.html' in path_lower or '.htm' in path_lower else 0
        features['path_has_php'] = 1 if '.php' in path_lower else 0
        features['path_has_asp'] = 1 if '.asp' in path_lower or '.aspx' in path_lower else 0
        
        # Directory traversal attempt
        features['has_directory_traversal'] = 1 if '../' in path or '..\\' in path else 0
        
        # Hidden file access attempt
        features['accesses_hidden_file'] = 1 if '/.' in path else 0
        
        # Path contains session-like tokens
        session_pattern = re.compile(r'/[a-f0-9]{24,}/|/[A-Za-z0-9]{24,}/', re.IGNORECASE)
        features['has_session_token_path'] = 1 if session_pattern.search(path) else 0
        
        # Long random-looking path segments
        segments = [s for s in path.split('/') if s]
        long_random_segments = [s for s in segments if len(s) > 20 and self._calculate_shannon_entropy(s) > 3.5]
        features['suspicious_path_segments'] = len(long_random_segments)
        
        return features
    
    def _extract_query_features(self, parsed):
        """
        Feature Group 8: Query String Analysis
        Analyzes URL query parameters
        """
        features = {}
        
        query = parsed.query or ''
        
        if not query:
            features['query_has_email'] = 0
            features['query_has_redirect'] = 0
            features['query_has_credential_param'] = 0
            features['query_has_encoded_url'] = 0
            features['query_avg_value_length'] = 0
            features['query_max_value_length'] = 0
            features['query_has_suspicious_param'] = 0
            return features
        
        query_lower = query.lower()
        params = parse_qs(query)
        
        # Email in query
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        features['query_has_email'] = 1 if email_pattern.search(query) else 0
        
        # Redirect URL in query
        redirect_params = ['url', 'redirect', 'return', 'next', 'goto', 'continue', 'dest', 'destination', 'rurl', 'returnurl']
        features['query_has_redirect'] = 1 if any(p in query_lower for p in redirect_params) else 0
        
        # Credential-related parameters
        cred_params = ['password', 'passwd', 'pwd', 'pass', 'token', 'apikey', 'api_key', 'secret', 'auth', 'session']
        features['query_has_credential_param'] = 1 if any(p in query_lower for p in cred_params) else 0
        
        # Encoded URL in query (potential redirect attack)
        features['query_has_encoded_url'] = 1 if 'http%3a' in query_lower or 'https%3a' in query_lower else 0
        
        # Query value analysis
        all_values = [v for values in params.values() for v in values]
        if all_values:
            features['query_avg_value_length'] = sum(len(v) for v in all_values) / len(all_values)
            features['query_max_value_length'] = max(len(v) for v in all_values)
        else:
            features['query_avg_value_length'] = 0
            features['query_max_value_length'] = 0
        
        # Suspicious parameter names
        suspicious_params = ['cmd', 'exec', 'script', 'shell', 'eval', 'action']
        features['query_has_suspicious_param'] = 1 if any(p in query_lower for p in suspicious_params) else 0
        
        return features
    
    def _extract_obfuscation_features(self, url, parsed):
        """
        Feature Group 9: Obfuscation Detection
        Detects various URL obfuscation techniques
        """
        features = {}
        
        # URL decoded for analysis
        decoded_url = unquote(url)
        
        # Double encoding detection
        double_decoded = unquote(decoded_url)
        features['has_double_encoding'] = 1 if double_decoded != decoded_url else 0
        
        # Null byte injection
        features['has_null_byte'] = 1 if '%00' in url or '\x00' in decoded_url else 0
        
        # Unicode obfuscation
        features['has_unicode_obfuscation'] = 1 if len(decoded_url.encode('utf-8')) != len(decoded_url) else 0
        
        # Long encoded sequences
        encoded_sequences = re.findall(r'(%[0-9A-Fa-f]{2}){3,}', url)
        features['long_encoded_sequence_count'] = len(encoded_sequences)
        
        # Mixed case obfuscation (HtTp, HttpS)
        scheme = parsed.scheme
        features['has_mixed_case_scheme'] = 1 if scheme != scheme.lower() and scheme != scheme.upper() else 0
        
        # Deceptive path separators
        features['has_backslash'] = 1 if '\\' in url else 0
        
        # Zero-width characters (used for phishing)
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff']
        features['has_zero_width_chars'] = 1 if any(c in decoded_url for c in zero_width_chars) else 0
        
        # Excessive dots (subdomain abuse)
        netloc = parsed.netloc
        features['excessive_dots'] = 1 if netloc.count('.') > 4 else 0
        
        return features
    
    def _extract_homograph_features(self, url, extracted):
        """
        Feature Group 10: Homograph Attack Detection
        Detects IDN homograph attacks using similar-looking characters
        """
        features = {}
        
        domain = extracted.domain or ''
        
        # Check for Cyrillic characters that look like Latin
        homograph_chars = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ո': 'n',
            'ν': 'v', 'ω': 'w', 'ք': 'q', 'ӏ': 'l', 'ḿ': 'm', 'ţ': 't', 'ż': 'z',
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'b', '7': 't',
            '8': 'b', '9': 'g'
        }
        
        homograph_count = sum(1 for c in domain if c in homograph_chars)
        features['homograph_char_count'] = homograph_count
        features['has_homograph_chars'] = 1 if homograph_count > 0 else 0
        
        # Mixed script detection (Latin + Cyrillic, etc.)
        has_latin = any('a' <= c.lower() <= 'z' for c in domain)
        has_non_latin = any(ord(c) > 127 for c in domain)
        features['has_mixed_scripts'] = 1 if has_latin and has_non_latin else 0
        
        # Leet speak detection (common substitutions)
        leet_patterns = {'1': 'i', '3': 'e', '4': 'a', '5': 's', '0': 'o', '7': 't', '@': 'a'}
        leet_count = sum(1 for c in domain if c in leet_patterns)
        features['leet_speak_count'] = leet_count
        
        # Check if normalizing homographs reveals a brand
        normalized_domain = self._normalize_homographs(domain)
        features['normalized_reveals_brand'] = 1 if any(brand in normalized_domain for brand in config.TARGETED_BRANDS) else 0
        
        return features
    
    def _extract_timing_features(self, extracted):
        """
        Feature Group 11: Domain Age/Freshness Approximations
        Uses static analysis to approximate timing-related features
        """
        features = {}
        
        domain = extracted.domain or ''
        
        # Domain contains year (often used in temporary phishing domains)
        current_year = datetime.datetime.now().year
        years_to_check = [str(y) for y in range(current_year - 2, current_year + 2)]
        features['domain_contains_year'] = 1 if any(y in domain for y in years_to_check) else 0
        
        # Domain contains date-like patterns
        date_pattern = re.compile(r'\d{2,4}[-/]\d{2}[-/]\d{2,4}|\d{6,8}')
        features['domain_contains_date'] = 1 if date_pattern.search(domain) else 0
        
        # Domain hash-like (appears auto-generated)
        features['domain_looks_generated'] = 1 if re.match(r'^[a-z0-9]{10,}$', domain.lower()) and self._calculate_shannon_entropy(domain) > 3.2 else 0
        
        return features
    
    def _extract_network_features(self, extracted):
        """
        Feature Group 12: Network-based Features
        DNS and connectivity analysis (with caching for efficiency)
        """
        features = {}
        
        domain = extracted.registered_domain
        
        if not domain:
            features['has_dns_record'] = 0
            features['has_mx_record'] = 0
            features['has_multiple_ips'] = 0
            features['ip_in_suspicious_range'] = 0
            return features
        
        # DNS A record check
        try:
            answers = self.dns_resolver.resolve(domain, 'A')
            features['has_dns_record'] = 1
            features['has_multiple_ips'] = 1 if len(answers) > 1 else 0
            
            # Check if IP is in suspicious ranges (simplified)
            ip_str = str(answers[0])
            features['ip_in_suspicious_range'] = self._is_suspicious_ip(ip_str)
        except:
            features['has_dns_record'] = 0
            features['has_multiple_ips'] = 0
            features['ip_in_suspicious_range'] = 0
        
        # DNS MX record check (legitimate sites often have MX)
        try:
            self.dns_resolver.resolve(domain, 'MX')
            features['has_mx_record'] = 1
        except:
            features['has_mx_record'] = 0
        
        return features
    
    # ==================== HELPER METHODS ====================
    
    def _calculate_shannon_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        return round(entropy, 4)
    
    def _max_consecutive_chars(self, text, char_test_func):
        """Find max consecutive characters matching a test function"""
        max_count = 0
        current_count = 0
        
        for char in text:
            if char_test_func(char):
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def _max_consecutive_consonants(self, text):
        """Find max consecutive consonants (useful for detecting random strings)"""
        consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
        max_count = 0
        current_count = 0
        
        for char in text:
            if char in consonants:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def _contains_ip_address(self, netloc):
        """Check if netloc contains an IP address"""
        # IPv4 pattern
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$')
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(r'^\[?[0-9a-fA-F:]+\]?(:\d+)?$')
        
        # Remove port for checking
        host = netloc.split(':')[0] if ':' in netloc and not netloc.startswith('[') else netloc
        
        return bool(ipv4_pattern.match(netloc) or ipv6_pattern.match(host))
    
    def _detect_typosquatting(self, domain):
        """
        Detect potential typosquatting by checking similarity to known brands
        Returns a score (higher = more suspicious)
        """
        max_score = 0
        
        for brand in config.TARGETED_BRANDS:
            if len(domain) < 3:
                continue
            
            # Check for character insertion (e.g., "appple")
            if brand in domain and len(domain) <= len(brand) + 3:
                max_score = max(max_score, 0.8)
            
            # Check for character replacement (e.g., "amaz0n", "g00gle")
            normalized = self._normalize_leet(domain)
            if brand == normalized or brand in normalized:
                max_score = max(max_score, 0.9)
            
            # Check for adjacent character swap (e.g., "googel")
            if self._are_swapped_variants(domain, brand):
                max_score = max(max_score, 0.85)
        
        return max_score
    
    def _normalize_leet(self, text):
        """Normalize leet speak to regular text"""
        leet_map = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}
        return ''.join(leet_map.get(c, c) for c in text.lower())
    
    def _are_swapped_variants(self, s1, s2):
        """Check if strings are variants with adjacent characters swapped"""
        if len(s1) != len(s2):
            return False
        
        diffs = [(i, c1, c2) for i, (c1, c2) in enumerate(zip(s1, s2)) if c1 != c2]
        
        if len(diffs) == 2:
            i1, c1_1, c1_2 = diffs[0]
            i2, c2_1, c2_2 = diffs[1]
            if i2 - i1 == 1 and c1_1 == c2_2 and c1_2 == c2_1:
                return True
        
        return False
    
    def _has_brand_suspicious_suffix(self, domain):
        """Check if domain has brand name followed by suspicious suffix"""
        suspicious_suffixes = ['login', 'secure', 'verify', 'update', 'account', 'signin', 'auth', 'confirm']
        
        for brand in config.TARGETED_BRANDS:
            for suffix in suspicious_suffixes:
                if brand + suffix in domain or brand + '-' + suffix in domain:
                    return 1
        return 0
    
    def _normalize_homographs(self, text):
        """Normalize homograph characters to their ASCII equivalents"""
        homograph_map = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ո': 'n',
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's'
        }
        return ''.join(homograph_map.get(c, c) for c in text.lower())
    
    def _is_suspicious_ip(self, ip_str):
        """Check if IP is in commonly abused ranges"""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return 0
            
            first_octet = int(parts[0])
            
            # Private ranges (shouldn't be public-facing)
            if first_octet == 10:
                return 1
            if first_octet == 172 and 16 <= int(parts[1]) <= 31:
                return 1
            if first_octet == 192 and int(parts[1]) == 168:
                return 1
            
            # Localhost
            if first_octet == 127:
                return 1
            
            return 0
        except:
            return 0
    
    def _get_default_features(self):
        """Return default feature values for error cases"""
        return {name: 0 for name in self.get_feature_names()}
    
    def get_feature_names(self):
        """Get list of all feature names"""
        # Extract features from a sample URL to get names
        sample_features = self.extract_all_features("https://www.example.com/test")
        return list(sample_features.keys())


# For testing
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.tk/verify?user=test@email.com",
        "http://192.168.1.1/login.php",
        "https://secure-amaz0n-update.xyz/signin",
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        print('='*60)
        
        features = extractor.extract_all_features(url)
        
        # Show suspicious features
        print("\nKey Features:")
        for name, value in features.items():
            if value != 0:
                print(f"  {name}: {value}")
