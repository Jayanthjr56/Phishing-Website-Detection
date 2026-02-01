"""
Quick Test Script for Phishing Detector
Tests the feature extraction and detection without full training
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_extractor import FeatureExtractor

def test_feature_extraction():
    """Test feature extraction on sample URLs"""
    print("\n" + "="*70)
    print("FEATURE EXTRACTION TEST")
    print("="*70)
    
    extractor = FeatureExtractor()
    
    # Sample URLs to test
    test_cases = [
        {
            'url': 'https://www.google.com',
            'expected': 'legitimate',
            'reason': 'Well-known legitimate domain'
        },
        {
            'url': 'https://www.microsoft.com/en-us/windows',
            'expected': 'legitimate',
            'reason': 'Well-known legitimate domain with path'
        },
        {
            'url': 'http://paypal-secure-login.tk/verify?user=test@email.com',
            'expected': 'phishing',
            'reason': 'Brand in domain, suspicious TLD, suspicious keywords'
        },
        {
            'url': 'http://192.168.1.1/admin/login.php',
            'expected': 'suspicious',
            'reason': 'IP address instead of domain'
        },
        {
            'url': 'https://secure-banking-update.xyz/signin/account',
            'expected': 'phishing',
            'reason': 'Suspicious TLD, multiple suspicious keywords'
        },
        {
            'url': 'http://amaz0n-verify-account.ml/update',
            'expected': 'phishing',
            'reason': 'Typosquatting, suspicious TLD, suspicious keywords'
        },
        {
            'url': 'https://github.com/user/repo',
            'expected': 'legitimate',
            'reason': 'Well-known legitimate domain'
        },
        {
            'url': 'https://login-facebook.suspicious-site.com/auth',
            'expected': 'phishing',
            'reason': 'Brand in subdomain'
        },
        {
            'url': 'http://xn--80ak6aa92e.com',
            'expected': 'suspicious',
            'reason': 'Punycode domain (IDN)'
        },
        {
            'url': 'https://www.amazon.com/dp/B08N5WRWNW',
            'expected': 'legitimate',
            'reason': 'Real Amazon product URL'
        }
    ]
    
    for test in test_cases:
        url = test['url']
        expected = test['expected']
        reason = test['reason']
        
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        print(f"Expected: {expected.upper()}")
        print(f"Reason: {reason}")
        print('-'*60)
        
        features = extractor.extract_all_features(url)
        
        # Show key suspicious features
        suspicious_features = []
        safe_features = []
        
        # Check suspicious indicators
        if features.get('has_ip_address'):
            suspicious_features.append('Uses IP address')
        if features.get('brand_in_subdomain'):
            suspicious_features.append('Brand name in subdomain')
        if features.get('brand_in_path') and not features.get('brand_in_domain'):
            suspicious_features.append('Brand in path, not domain')
        if features.get('is_suspicious_tld'):
            suspicious_features.append('Suspicious TLD')
        if features.get('suspicious_keyword_count', 0) > 0:
            suspicious_features.append(f"{features.get('suspicious_keyword_count')} suspicious keywords")
        if features.get('brand_typosquat_score', 0) > 0.5:
            suspicious_features.append('Possible typosquatting')
        if features.get('has_punycode'):
            suspicious_features.append('Uses punycode (IDN)')
        if features.get('uses_free_hosting'):
            suspicious_features.append('Free hosting provider')
        if features.get('has_at_symbol'):
            suspicious_features.append('@ symbol in URL')
        if features.get('is_http') and not features.get('is_https'):
            suspicious_features.append('No HTTPS')
        
        # Check safe indicators
        if features.get('is_https'):
            safe_features.append('Uses HTTPS')
        if features.get('is_trusted_tld'):
            safe_features.append('Trusted TLD')
        if features.get('has_dns_record'):
            safe_features.append('Valid DNS record')
        if features.get('has_mx_record'):
            safe_features.append('Has MX record')
        
        print("\nSUSPICIOUS INDICATORS:")
        if suspicious_features:
            for f in suspicious_features:
                print(f"  ⚠ {f}")
        else:
            print("  (none)")
        
        print("\nSAFE INDICATORS:")
        if safe_features:
            for f in safe_features:
                print(f"  ✓ {f}")
        else:
            print("  (none)")
        
        print(f"\nKey feature values:")
        print(f"  URL length: {features.get('url_length')}")
        print(f"  URL entropy: {features.get('url_entropy', 0):.2f}")
        print(f"  Domain entropy: {features.get('domain_entropy', 0):.2f}")
        print(f"  Subdomain count: {features.get('subdomain_count')}")
        print(f"  Path depth: {features.get('path_depth')}")
    
    print("\n" + "="*70)
    print("FEATURE EXTRACTION TEST COMPLETE")
    print("="*70)
    print(f"\nTotal features extracted: {len(features)}")
    print("\nFeature names:")
    for i, name in enumerate(sorted(features.keys())):
        print(f"  {i+1:2}. {name}")


def main():
    """Run the test"""
    test_feature_extraction()


if __name__ == "__main__":
    main()
