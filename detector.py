"""
Phishing Detector Module
Real-time URL classification for phishing detection
"""

import os
import numpy as np
import joblib
from datetime import datetime
import json

import config
from feature_extractor import FeatureExtractor


class PhishingDetector:
    """
    Real-time phishing detection using trained ML model
    Classifies URLs as Legitimate, Suspicious, or Phishing
    """
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.feature_extractor = FeatureExtractor()
        self.is_loaded = False
        
        # Load model on initialization
        self._load_model()
    
    def _load_model(self):
        """Load the trained model, scaler, and feature names"""
        try:
            if not os.path.exists(config.MODEL_FILE):
                print("[WARNING] No trained model found. Please train the model first.")
                return False
            
            self.model = joblib.load(config.MODEL_FILE)
            self.scaler = joblib.load(config.SCALER_FILE)
            self.feature_names = joblib.load(config.FEATURE_NAMES_FILE)
            self.is_loaded = True
            
            print("[INFO] Phishing detection model loaded successfully")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False
    
    def check_url(self, url):
        """
        Check a single URL for phishing
        
        Args:
            url: The URL to check
        
        Returns:
            dict with classification result and details
        """
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'classification': 'Unknown',
            'confidence': 0.0,
            'phishing_probability': 0.0,
            'risk_level': 'Unknown',
            'risk_factors': [],
            'safe_factors': [],
            'details': {}
        }
        
        # Validate URL
        if not url or not isinstance(url, str):
            result['error'] = 'Invalid URL provided'
            return result
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            result['url'] = url
        
        # Check if model is loaded
        if not self.is_loaded:
            # Try to reload
            if not self._load_model():
                result['error'] = 'Model not available. Please train the model first.'
                return result
        
        try:
            # Extract features
            features = self.feature_extractor.extract_all_features(url)
            
            # Store raw features for analysis
            result['details']['extracted_features'] = {
                k: float(v) if isinstance(v, (int, float, np.floating, np.integer)) else v 
                for k, v in features.items()
            }
            
            # Prepare feature vector
            feature_vector = self._prepare_feature_vector(features)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform([feature_vector])
            
            # Get prediction and probabilities
            prediction = self.model.predict(feature_vector_scaled)[0]
            probabilities = self.model.predict_proba(feature_vector_scaled)[0]
            
            phishing_prob = float(probabilities[1])
            legitimate_prob = float(probabilities[0])
            
            result['phishing_probability'] = round(phishing_prob, 4)
            result['legitimate_probability'] = round(legitimate_prob, 4)
            
            # Classify based on thresholds
            if phishing_prob < config.LEGITIMATE_THRESHOLD:
                result['classification'] = 'Legitimate'
                result['risk_level'] = 'Low'
                result['confidence'] = round(legitimate_prob, 4)
            elif phishing_prob > config.SUSPICIOUS_THRESHOLD:
                result['classification'] = 'Phishing'
                result['risk_level'] = 'High'
                result['confidence'] = round(phishing_prob, 4)
            else:
                result['classification'] = 'Suspicious'
                result['risk_level'] = 'Medium'
                result['confidence'] = round(max(phishing_prob, legitimate_prob), 4)
            
            # Analyze risk and safe factors
            result['risk_factors'] = self._identify_risk_factors(features)
            result['safe_factors'] = self._identify_safe_factors(features)
            
            # Add summary
            result['summary'] = self._generate_summary(result)
            
        except Exception as e:
            result['error'] = f'Analysis failed: {str(e)}'
            result['classification'] = 'Unknown'
            result['risk_level'] = 'Unknown'
        
        return result
    
    def check_urls(self, urls):
        """
        Check multiple URLs for phishing
        
        Args:
            urls: List of URLs to check
        
        Returns:
            List of classification results
        """
        results = []
        for url in urls:
            result = self.check_url(url)
            results.append(result)
        return results
    
    def _prepare_feature_vector(self, features):
        """Prepare feature vector in correct order"""
        feature_vector = []
        
        for feature_name in self.feature_names:
            if feature_name in features:
                value = features[feature_name]
                # Convert to float, handle any edge cases
                if isinstance(value, bool):
                    value = 1.0 if value else 0.0
                elif value is None:
                    value = 0.0
                else:
                    try:
                        value = float(value)
                    except (ValueError, TypeError):
                        value = 0.0
                feature_vector.append(value)
            else:
                feature_vector.append(0.0)
        
        return feature_vector
    
    def _identify_risk_factors(self, features):
        """Identify factors that increase phishing risk"""
        risk_factors = []
        
        # High-risk indicators
        if features.get('has_ip_address', 0):
            risk_factors.append({
                'factor': 'IP Address Used',
                'description': 'URL uses IP address instead of domain name',
                'severity': 'high'
            })
        
        if features.get('is_http', 0) and not features.get('is_https', 0):
            risk_factors.append({
                'factor': 'No HTTPS',
                'description': 'Connection is not encrypted (HTTP only)',
                'severity': 'medium'
            })
        
        if features.get('brand_in_subdomain', 0):
            risk_factors.append({
                'factor': 'Brand in Subdomain',
                'description': 'Known brand name appears in subdomain (common phishing technique)',
                'severity': 'high'
            })
        
        if features.get('brand_in_path', 0) and not features.get('brand_in_domain', 0):
            risk_factors.append({
                'factor': 'Brand in Path Only',
                'description': 'Brand name in URL path but not in main domain',
                'severity': 'medium'
            })
        
        if features.get('is_suspicious_tld', 0):
            risk_factors.append({
                'factor': 'Suspicious TLD',
                'description': 'Uses a top-level domain commonly associated with abuse',
                'severity': 'medium'
            })
        
        if features.get('suspicious_keyword_count', 0) > 2:
            risk_factors.append({
                'factor': 'Multiple Suspicious Keywords',
                'description': f"Contains {features.get('suspicious_keyword_count', 0)} suspicious keywords (login, verify, etc.)",
                'severity': 'medium'
            })
        
        if features.get('has_at_symbol', 0):
            risk_factors.append({
                'factor': '@ Symbol in URL',
                'description': 'URL contains @ symbol which can hide real destination',
                'severity': 'high'
            })
        
        if features.get('has_double_encoding', 0):
            risk_factors.append({
                'factor': 'Double URL Encoding',
                'description': 'URL uses double encoding to obfuscate content',
                'severity': 'high'
            })
        
        if features.get('has_punycode', 0):
            risk_factors.append({
                'factor': 'Internationalized Domain',
                'description': 'Uses punycode/IDN which could be a homograph attack',
                'severity': 'medium'
            })
        
        if features.get('has_homograph_chars', 0):
            risk_factors.append({
                'factor': 'Homograph Characters',
                'description': 'Contains characters that look like others (potential lookalike attack)',
                'severity': 'high'
            })
        
        if features.get('brand_typosquat_score', 0) > 0.7:
            risk_factors.append({
                'factor': 'Potential Typosquatting',
                'description': 'Domain appears to impersonate a known brand with typos',
                'severity': 'high'
            })
        
        if features.get('is_shortened', 0):
            risk_factors.append({
                'factor': 'Shortened URL',
                'description': 'Uses URL shortener which hides destination',
                'severity': 'medium'
            })
        
        if features.get('uses_free_hosting', 0):
            risk_factors.append({
                'factor': 'Free Hosting Provider',
                'description': 'Hosted on a free platform commonly used for phishing',
                'severity': 'medium'
            })
        
        if features.get('subdomain_count', 0) > 3:
            risk_factors.append({
                'factor': 'Excessive Subdomains',
                'description': f"URL has {features.get('subdomain_count', 0)} subdomain levels",
                'severity': 'medium'
            })
        
        if features.get('url_entropy', 0) > 4.5:
            risk_factors.append({
                'factor': 'High URL Entropy',
                'description': 'URL contains random-looking strings',
                'severity': 'low'
            })
        
        if features.get('has_phishing_path', 0):
            risk_factors.append({
                'factor': 'Suspicious Path Pattern',
                'description': 'URL path matches common phishing patterns',
                'severity': 'medium'
            })
        
        if features.get('query_has_redirect', 0):
            risk_factors.append({
                'factor': 'Redirect Parameter',
                'description': 'URL contains redirect parameters',
                'severity': 'low'
            })
        
        if features.get('domain_looks_generated', 0):
            risk_factors.append({
                'factor': 'Generated Domain Name',
                'description': 'Domain appears to be randomly generated',
                'severity': 'medium'
            })
        
        if features.get('has_dns_record', 0) == 0:
            risk_factors.append({
                'factor': 'No DNS Record',
                'description': 'Domain has no DNS record (may be invalid or very new)',
                'severity': 'medium'
            })
        
        return risk_factors
    
    def _identify_safe_factors(self, features):
        """Identify factors that indicate legitimacy"""
        safe_factors = []
        
        if features.get('is_https', 0):
            safe_factors.append({
                'factor': 'HTTPS Enabled',
                'description': 'Connection is encrypted'
            })
        
        if features.get('is_trusted_tld', 0):
            safe_factors.append({
                'factor': 'Trusted TLD',
                'description': 'Uses a well-established top-level domain'
            })
        
        if features.get('has_mx_record', 0):
            safe_factors.append({
                'factor': 'Has MX Record',
                'description': 'Domain has email infrastructure configured'
            })
        
        if features.get('is_legitimate_subdomain', 0):
            safe_factors.append({
                'factor': 'Standard Subdomain',
                'description': 'Uses common legitimate subdomain (www, mail, etc.)'
            })
        
        if features.get('url_length', 0) < 50:
            safe_factors.append({
                'factor': 'Short URL',
                'description': 'URL is concise and readable'
            })
        
        if features.get('domain_entropy', 0) < 3.0:
            safe_factors.append({
                'factor': 'Readable Domain',
                'description': 'Domain name appears human-readable'
            })
        
        if features.get('suspicious_keyword_count', 0) == 0:
            safe_factors.append({
                'factor': 'No Suspicious Keywords',
                'description': 'URL does not contain common phishing keywords'
            })
        
        if features.get('has_multiple_ips', 0):
            safe_factors.append({
                'factor': 'Multiple IP Addresses',
                'description': 'Domain resolves to multiple IPs (CDN/load balancing)'
            })
        
        return safe_factors
    
    def _generate_summary(self, result):
        """Generate a human-readable summary of the analysis"""
        classification = result['classification']
        confidence = result['confidence'] * 100
        risk_count = len(result['risk_factors'])
        safe_count = len(result['safe_factors'])
        
        if classification == 'Legitimate':
            summary = f"This URL appears to be SAFE with {confidence:.1f}% confidence. "
            summary += f"Found {safe_count} positive indicators and {risk_count} potential concerns."
        elif classification == 'Phishing':
            summary = f"WARNING: This URL is likely PHISHING with {confidence:.1f}% confidence. "
            summary += f"Found {risk_count} risk factors. Do NOT enter any personal information."
        else:
            summary = f"This URL is SUSPICIOUS and requires caution. "
            summary += f"Found {risk_count} risk factors and {safe_count} safe indicators. "
            summary += "Verify the source before proceeding."
        
        return summary
    
    def get_detailed_report(self, url):
        """
        Get a detailed human-readable report for a URL
        
        Args:
            url: The URL to analyze
        
        Returns:
            Formatted string report
        """
        result = self.check_url(url)
        
        report = []
        report.append("=" * 70)
        report.append("PHISHING DETECTION REPORT")
        report.append("=" * 70)
        report.append(f"\nURL: {result['url']}")
        report.append(f"Analyzed: {result['timestamp']}")
        report.append("")
        
        # Classification banner
        if result['classification'] == 'Legitimate':
            report.append("┌" + "─" * 68 + "┐")
            report.append("│" + "  ✓ SAFE - This URL appears to be legitimate".center(68) + "│")
            report.append("└" + "─" * 68 + "┘")
        elif result['classification'] == 'Phishing':
            report.append("┌" + "─" * 68 + "┐")
            report.append("│" + "  ⚠ DANGER - This URL is likely phishing".center(68) + "│")
            report.append("└" + "─" * 68 + "┘")
        else:
            report.append("┌" + "─" * 68 + "┐")
            report.append("│" + "  ? SUSPICIOUS - Exercise caution".center(68) + "│")
            report.append("└" + "─" * 68 + "┘")
        
        report.append(f"\nClassification: {result['classification']}")
        report.append(f"Risk Level: {result['risk_level']}")
        report.append(f"Confidence: {result['confidence']*100:.1f}%")
        report.append(f"Phishing Probability: {result['phishing_probability']*100:.1f}%")
        
        # Risk factors
        if result['risk_factors']:
            report.append("\n" + "-" * 40)
            report.append("RISK FACTORS:")
            report.append("-" * 40)
            for factor in result['risk_factors']:
                severity_icon = "⚠" if factor['severity'] == 'high' else "!" if factor['severity'] == 'medium' else "•"
                report.append(f"\n{severity_icon} {factor['factor']} [{factor['severity'].upper()}]")
                report.append(f"  {factor['description']}")
        
        # Safe factors
        if result['safe_factors']:
            report.append("\n" + "-" * 40)
            report.append("SAFE INDICATORS:")
            report.append("-" * 40)
            for factor in result['safe_factors']:
                report.append(f"\n✓ {factor['factor']}")
                report.append(f"  {factor['description']}")
        
        # Summary
        if 'summary' in result:
            report.append("\n" + "-" * 40)
            report.append("SUMMARY:")
            report.append("-" * 40)
            report.append(result['summary'])
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)


def demo():
    """Demonstrate the phishing detector"""
    detector = PhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.microsoft.com/en-us/account",
        "http://paypal-secure-login.tk/verify?user=test@email.com",
        "https://secure-banking-update.xyz/signin/account",
        "http://192.168.1.1/admin/login.php",
        "https://amazon.com",
        "http://amaz0n-account-verify.ml/update",
        "https://login-facebook.suspicious-site.com/auth",
    ]
    
    print("\n" + "="*70)
    print("PHISHING DETECTOR DEMO")
    print("="*70)
    
    for url in test_urls:
        print("\n")
        print(detector.get_detailed_report(url))


if __name__ == "__main__":
    demo()
