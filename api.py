"""
Flask API for Real-time Phishing Detection
Provides REST API endpoints for URL checking
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import os
import logging
from datetime import datetime

import config
from detector import PhishingDetector

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize detector
detector = None


def get_detector():
    """Get or initialize the phishing detector"""
    global detector
    if detector is None:
        detector = PhishingDetector()
    return detector


@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    det = get_detector()
    return jsonify({
        'status': 'healthy',
        'model_loaded': det.is_loaded,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/check', methods=['POST'])
def check_url():
    """
    Check a single URL for phishing
    
    Request body:
        {"url": "https://example.com"}
    
    Returns:
        Classification result with details
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing URL in request body',
                'example': {'url': 'https://example.com'}
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'Empty URL provided'}), 400
        
        # Get detector and check URL
        det = get_detector()
        result = det.check_url(url)
        
        logger.info(f"Checked URL: {url} -> {result['classification']}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error checking URL: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/check-batch', methods=['POST'])
def check_urls_batch():
    """
    Check multiple URLs for phishing
    
    Request body:
        {"urls": ["https://example1.com", "https://example2.com"]}
    
    Returns:
        List of classification results
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'Missing URLs in request body',
                'example': {'urls': ['https://example1.com', 'https://example2.com']}
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be a list'}), 400
        
        if len(urls) > 100:
            return jsonify({'error': 'Maximum 100 URLs per request'}), 400
        
        # Get detector and check URLs
        det = get_detector()
        results = det.check_urls(urls)
        
        logger.info(f"Batch checked {len(urls)} URLs")
        
        return jsonify({
            'total': len(results),
            'results': results
        })
    
    except Exception as e:
        logger.error(f"Error in batch check: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/report', methods=['POST'])
def get_report():
    """
    Get a detailed text report for a URL
    
    Request body:
        {"url": "https://example.com"}
    
    Returns:
        Detailed text report
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL in request body'}), 400
        
        url = data['url'].strip()
        
        det = get_detector()
        report = det.get_detailed_report(url)
        
        return jsonify({
            'url': url,
            'report': report
        })
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get model and detector statistics"""
    try:
        det = get_detector()
        
        stats = {
            'model_loaded': det.is_loaded,
            'feature_count': len(det.feature_names) if det.feature_names else 0,
            'thresholds': {
                'legitimate': config.LEGITIMATE_THRESHOLD,
                'suspicious': config.SUSPICIOUS_THRESHOLD
            },
            'supported_classifications': ['Legitimate', 'Suspicious', 'Phishing']
        }
        
        return jsonify(stats)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


def run_api(host=None, port=None, debug=None):
    """Run the Flask API server"""
    host = host or config.API_HOST
    port = port or config.API_PORT
    debug = debug if debug is not None else config.DEBUG_MODE
    
    print("\n" + "="*60)
    print("PHISHING DETECTION API SERVER")
    print("="*60)
    print(f"\n  Starting server at http://{host}:{port}")
    print(f"\n  API Endpoints:")
    print(f"    POST /api/check       - Check single URL")
    print(f"    POST /api/check-batch - Check multiple URLs")
    print(f"    POST /api/report      - Get detailed report")
    print(f"    GET  /api/health      - Health check")
    print(f"    GET  /api/stats       - Model statistics")
    print(f"\n  Web Interface: http://localhost:{port}")
    print("\n" + "="*60 + "\n")
    
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_api()
