"""
Phishing Website Detection System
=================================

A complete machine learning-based phishing detection system that:
1. Downloads and processes legitimate (Tranco) and phishing URL datasets
2. Extracts 80+ custom features from URLs
3. Trains an ensemble ML model for classification
4. Provides real-time detection via CLI and Web API

Usage:
------
    # Full pipeline (download data, train model, start API)
    python main.py --full
    
    # Train model only
    python main.py --train
    
    # Start API server only (requires trained model)
    python main.py --api
    
    # Check a single URL
    python main.py --check "https://example.com"
    
    # Interactive mode
    python main.py --interactive

Author: Phishing Detection Project
License: MIT
"""

import argparse
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from data_collector import DataCollector
from model_trainer import train_full_pipeline
from detector import PhishingDetector


def run_full_pipeline():
    """Run the complete pipeline: collect data, train model, start API"""
    print("\n" + "="*70)
    print("PHISHING DETECTION SYSTEM - FULL PIPELINE")
    print("="*70)
    
    # Step 1: Collect data
    print("\n[STEP 1/3] Collecting training data...")
    collector = DataCollector()
    df = collector.create_training_dataset()
    
    if df is None:
        print("[ERROR] Failed to collect training data")
        return
    
    # Step 2: Train model
    print("\n[STEP 2/3] Training ML model...")
    trainer = train_full_pipeline(max_samples=10000)  # Adjust for full training
    
    # Step 3: Start API
    print("\n[STEP 3/3] Starting API server...")
    from api import run_api
    run_api()


def train_model(max_samples=None):
    """Train the phishing detection model"""
    print("\n" + "="*70)
    print("TRAINING PHISHING DETECTION MODEL")
    print("="*70)
    
    # Check if data exists
    if not os.path.exists(config.PROCESSED_DATA_FILE):
        print("[INFO] Training data not found. Collecting data first...")
        collector = DataCollector()
        collector.create_training_dataset()
    
    # Train model
    trainer = train_full_pipeline(max_samples=max_samples)
    
    print("\n[SUCCESS] Model training complete!")
    print(f"[INFO] Model saved to: {config.MODEL_FILE}")


def start_api():
    """Start the API server"""
    # Check if model exists
    if not os.path.exists(config.MODEL_FILE):
        print("[ERROR] No trained model found. Please train the model first.")
        print("[INFO] Run: python main.py --train")
        return
    
    from api import run_api
    run_api()


def check_single_url(url):
    """Check a single URL for phishing"""
    detector = PhishingDetector()
    
    if not detector.is_loaded:
        print("[ERROR] Model not loaded. Please train the model first.")
        print("[INFO] Run: python main.py --train")
        return
    
    report = detector.get_detailed_report(url)
    print(report)


def interactive_mode():
    """Interactive URL checking mode"""
    print("\n" + "="*70)
    print("PHISHING DETECTOR - INTERACTIVE MODE")
    print("="*70)
    print("\nEnter URLs to check. Type 'quit' or 'exit' to stop.\n")
    
    detector = PhishingDetector()
    
    if not detector.is_loaded:
        print("[ERROR] Model not loaded. Please train the model first.")
        print("[INFO] Run: python main.py --train")
        return
    
    while True:
        try:
            url = input("\nEnter URL: ").strip()
            
            if url.lower() in ['quit', 'exit', 'q']:
                print("\nGoodbye!")
                break
            
            if not url:
                continue
            
            # Check URL
            result = detector.check_url(url)
            
            # Display result
            classification = result['classification']
            confidence = result['confidence'] * 100
            risk_level = result['risk_level']
            
            if classification == 'Legitimate':
                print(f"\n  ✓ SAFE - {classification} ({confidence:.1f}% confidence)")
            elif classification == 'Phishing':
                print(f"\n  ⚠ DANGER - {classification} ({confidence:.1f}% confidence)")
            else:
                print(f"\n  ? SUSPICIOUS - {classification} ({confidence:.1f}% confidence)")
            
            print(f"  Risk Level: {risk_level}")
            print(f"  Phishing Probability: {result['phishing_probability']*100:.1f}%")
            
            # Show top risk factors
            if result['risk_factors']:
                print("\n  Risk Factors:")
                for factor in result['risk_factors'][:3]:
                    print(f"    • {factor['factor']}: {factor['description']}")
            
            # Ask for detailed report
            detail = input("\nShow detailed report? (y/n): ").strip().lower()
            if detail == 'y':
                print(detector.get_detailed_report(url))
                
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"[ERROR] {e}")


def show_info():
    """Show project information"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                 PHISHING WEBSITE DETECTION SYSTEM                    ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  A machine learning-based phishing URL detection system with:       ║
║                                                                      ║
║  ✓ 80+ custom-engineered features                                   ║
║  ✓ Ensemble ML model (Random Forest + Gradient Boosting + LR)       ║
║  ✓ Real-time detection via REST API                                 ║
║  ✓ Beautiful web interface                                          ║
║  ✓ Three-tier classification (Legitimate, Suspicious, Phishing)     ║
║                                                                      ║
║  Data Sources:                                                       ║
║  • Legitimate: Tranco Top Sites List                                ║
║  • Phishing: Mitchell Krogza's Phishing Database                    ║
║                                                                      ║
║  Usage:                                                              ║
║    python main.py --full        Full pipeline (train + API)         ║
║    python main.py --train       Train model only                    ║
║    python main.py --api         Start API server                    ║
║    python main.py --check URL   Check single URL                    ║
║    python main.py --interactive Interactive mode                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(
        description='Phishing Website Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --full                    Run full pipeline
  python main.py --train                   Train the model
  python main.py --train --samples 5000    Train with 5000 samples
  python main.py --api                     Start API server
  python main.py --check https://google.com  Check a URL
  python main.py --interactive             Interactive mode
        """
    )
    
    parser.add_argument('--full', action='store_true',
                        help='Run full pipeline (collect data, train, start API)')
    parser.add_argument('--train', action='store_true',
                        help='Train the phishing detection model')
    parser.add_argument('--samples', type=int, default=None,
                        help='Maximum number of samples for training')
    parser.add_argument('--api', action='store_true',
                        help='Start the API server')
    parser.add_argument('--check', type=str, metavar='URL',
                        help='Check a single URL')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Start interactive mode')
    parser.add_argument('--info', action='store_true',
                        help='Show project information')
    
    args = parser.parse_args()
    
    # No arguments - show info
    if len(sys.argv) == 1:
        show_info()
        return
    
    if args.info:
        show_info()
    elif args.full:
        run_full_pipeline()
    elif args.train:
        train_model(max_samples=args.samples)
    elif args.api:
        start_api()
    elif args.check:
        check_single_url(args.check)
    elif args.interactive:
        interactive_mode()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
