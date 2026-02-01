"""
Data Collection Module
Downloads and processes legitimate and phishing URL datasets
"""

import os
import requests
import pandas as pd
from tqdm import tqdm
import time
import random
import config

class DataCollector:
    """Collects and processes URL datasets for training"""
    
    def __init__(self):
        self.tranco_url = config.TRANCO_URL
        self.phishing_url = config.PHISHING_URL
        
    def download_tranco_list(self, force_download=False):
        """
        Download the Tranco top sites list (legitimate websites)
        Returns a list of legitimate domains
        """
        if os.path.exists(config.TRANCO_FILE) and not force_download:
            print(f"[INFO] Tranco list already exists at {config.TRANCO_FILE}")
            return self._load_tranco_list()
        
        print("[INFO] Downloading Tranco top sites list...")
        try:
            response = requests.get(self.tranco_url, stream=True, timeout=60)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(config.TRANCO_FILE, 'wb') as f:
                with tqdm(total=total_size, unit='iB', unit_scale=True, desc="Downloading Tranco") as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            print(f"[SUCCESS] Tranco list saved to {config.TRANCO_FILE}")
            return self._load_tranco_list()
            
        except Exception as e:
            print(f"[ERROR] Failed to download Tranco list: {e}")
            return []
    
    def _load_tranco_list(self):
        """Load and parse the Tranco list"""
        domains = []
        try:
            with open(config.TRANCO_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain:
                            # Create full URLs from domains
                            domains.append(f"https://{domain}")
            print(f"[INFO] Loaded {len(domains)} legitimate domains")
        except Exception as e:
            print(f"[ERROR] Failed to load Tranco list: {e}")
        return domains
    
    def download_phishing_list(self, force_download=False):
        """
        Download the phishing URLs database
        Returns a list of phishing URLs
        """
        if os.path.exists(config.PHISHING_FILE) and not force_download:
            print(f"[INFO] Phishing list already exists at {config.PHISHING_FILE}")
            return self._load_phishing_list()
        
        print("[INFO] Downloading phishing URLs database...")
        try:
            response = requests.get(self.phishing_url, stream=True, timeout=60)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(config.PHISHING_FILE, 'wb') as f:
                with tqdm(total=total_size, unit='iB', unit_scale=True, desc="Downloading Phishing URLs") as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            print(f"[SUCCESS] Phishing URLs saved to {config.PHISHING_FILE}")
            return self._load_phishing_list()
            
        except Exception as e:
            print(f"[ERROR] Failed to download phishing list: {e}")
            return []
    
    def _load_phishing_list(self):
        """Load and parse the phishing URLs list"""
        urls = []
        try:
            with open(config.PHISHING_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        # Ensure URL has a scheme
                        if not url.startswith(('http://', 'https://')):
                            url = 'http://' + url
                        urls.append(url)
            print(f"[INFO] Loaded {len(urls)} phishing URLs")
        except Exception as e:
            print(f"[ERROR] Failed to load phishing list: {e}")
        return urls
    
    def create_training_dataset(self, force_download=False):
        """
        Create a balanced training dataset from both sources
        Returns a DataFrame with URLs and labels
        """
        print("\n" + "="*60)
        print("CREATING TRAINING DATASET")
        print("="*60 + "\n")
        
        # Download/load data
        legitimate_urls = self.download_tranco_list(force_download)
        phishing_urls = self.download_phishing_list(force_download)
        
        if not legitimate_urls or not phishing_urls:
            print("[ERROR] Failed to load required datasets")
            return None
        
        # Sample if datasets are too large
        if len(legitimate_urls) > config.MAX_LEGITIMATE_SAMPLES:
            print(f"[INFO] Sampling {config.MAX_LEGITIMATE_SAMPLES} legitimate URLs from {len(legitimate_urls)}")
            legitimate_urls = random.sample(legitimate_urls, config.MAX_LEGITIMATE_SAMPLES)
        
        if len(phishing_urls) > config.MAX_PHISHING_SAMPLES:
            print(f"[INFO] Sampling {config.MAX_PHISHING_SAMPLES} phishing URLs from {len(phishing_urls)}")
            phishing_urls = random.sample(phishing_urls, config.MAX_PHISHING_SAMPLES)
        
        # Create DataFrame
        data = []
        
        # Add legitimate URLs (label = 0)
        for url in legitimate_urls:
            data.append({'url': url, 'label': 0, 'label_name': 'legitimate'})
        
        # Add phishing URLs (label = 1)
        for url in phishing_urls:
            data.append({'url': url, 'label': 1, 'label_name': 'phishing'})
        
        df = pd.DataFrame(data)
        
        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save processed dataset
        df.to_csv(config.PROCESSED_DATA_FILE, index=False)
        print(f"\n[SUCCESS] Dataset saved to {config.PROCESSED_DATA_FILE}")
        print(f"[INFO] Total samples: {len(df)}")
        print(f"[INFO] Legitimate: {len(df[df['label'] == 0])}")
        print(f"[INFO] Phishing: {len(df[df['label'] == 1])}")
        
        return df
    
    def load_processed_dataset(self):
        """Load the processed dataset if it exists"""
        if os.path.exists(config.PROCESSED_DATA_FILE):
            df = pd.read_csv(config.PROCESSED_DATA_FILE)
            print(f"[INFO] Loaded processed dataset with {len(df)} samples")
            return df
        return None


def main():
    """Main function to collect and process data"""
    collector = DataCollector()
    
    # Create the training dataset
    df = collector.create_training_dataset(force_download=False)
    
    if df is not None:
        print("\n[INFO] Sample data:")
        print(df.head(10))
        
        print("\n[INFO] Dataset statistics:")
        print(df['label_name'].value_counts())


if __name__ == "__main__":
    main()
