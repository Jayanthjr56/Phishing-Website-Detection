"""
Configuration settings for Phishing Detection Project
"""

import os

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Create directories if they don't exist
for directory in [DATA_DIR, MODEL_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Data sources
TRANCO_URL = "https://tranco-list.eu/download/6G92X/full"
PHISHING_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"

# Data file paths
TRANCO_FILE = os.path.join(DATA_DIR, "tranco_list.csv")
PHISHING_FILE = os.path.join(DATA_DIR, "phishing_urls.txt")
PROCESSED_DATA_FILE = os.path.join(DATA_DIR, "processed_dataset.csv")
FEATURE_FILE = os.path.join(DATA_DIR, "features_dataset.csv")

# Model paths
MODEL_FILE = os.path.join(MODEL_DIR, "phishing_detector_model.joblib")
SCALER_FILE = os.path.join(MODEL_DIR, "feature_scaler.joblib")
FEATURE_NAMES_FILE = os.path.join(MODEL_DIR, "feature_names.joblib")

# Classification thresholds
LEGITIMATE_THRESHOLD = 0.3  # Below this = Legitimate
SUSPICIOUS_THRESHOLD = 0.7   # Above this = Phishing, Between = Suspicious

# Sampling settings (for faster training)
MAX_LEGITIMATE_SAMPLES = 50000
MAX_PHISHING_SAMPLES = 50000

# API Settings
API_HOST = "0.0.0.0"
API_PORT = 5000
DEBUG_MODE = True

# Feature extraction timeouts
DNS_TIMEOUT = 5
WHOIS_TIMEOUT = 10
SSL_TIMEOUT = 5

# Known legitimate TLDs (weighted scoring)
TRUSTED_TLDS = {'.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.io', '.de', '.fr', '.jp', '.au'}

# Suspicious TLDs (commonly abused)
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', 
                   '.info', '.biz', '.win', '.download', '.party', '.loan', '.racing', '.date',
                   '.review', '.trade', '.webcam', '.stream', '.accountant', '.science', '.faith'}

# Brand names commonly impersonated
TARGETED_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook', 
    'instagram', 'whatsapp', 'linkedin', 'twitter', 'dropbox', 'icloud', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'americanexpress', 'visa', 'mastercard',
    'ebay', 'walmart', 'target', 'costco', 'bestbuy', 'adobe', 'zoom', 'slack',
    'github', 'gitlab', 'bitbucket', 'office365', 'outlook', 'hotmail', 'yahoo',
    'aol', 'att', 'verizon', 'tmobile', 'sprint', 'comcast', 'spectrum', 'cox',
    'usps', 'fedex', 'ups', 'dhl', 'irs', 'ssa', 'dmv'
]

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
    'account', 'update', 'confirm', 'password', 'credential', 'authenticate',
    'suspend', 'suspended', 'unlock', 'locked', 'restore', 'recovery', 'urgent',
    'immediately', 'expire', 'expired', 'expiring', 'limited', 'offer', 'free',
    'winner', 'prize', 'reward', 'bonus', 'gift', 'claim', 'validate', 'validation',
    'customer', 'service', 'support', 'helpdesk', 'billing', 'invoice', 'payment',
    'refund', 'transaction', 'bank', 'credit', 'debit', 'card', 'ssn', 'social',
    'tax', 'irs', 'gov', 'official', 'alert', 'notice', 'warning', 'action-required',
    'webscr', 'cmd', 'dispatch', 'session', 'token', 'auth'
]

# Common legitimate subdomains
LEGITIMATE_SUBDOMAINS = ['www', 'mail', 'email', 'ftp', 'blog', 'shop', 'store', 
                          'api', 'cdn', 'static', 'assets', 'images', 'img', 
                          'admin', 'portal', 'secure', 'login', 'auth', 'm', 'mobile']

# URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'shorte.st', 'cutt.ly', 'rebrand.ly',
    'tiny.cc', 'shorturl.at', 'rb.gy', 'clck.ru', 'bc.vc', 'j.mp'
]

# Free hosting providers (often abused)
FREE_HOSTING_PROVIDERS = [
    '000webhostapp.com', 'weebly.com', 'wix.com', 'wordpress.com', 'blogspot.com',
    'sites.google.com', 'github.io', 'netlify.app', 'vercel.app', 'herokuapp.com',
    'firebaseapp.com', 'web.app', 'surge.sh', 'glitch.me', 'repl.co', 'replit.dev',
    'pythonanywhere.com', 'ngrok.io', 'serveo.net', 'localtunnel.me'
]
