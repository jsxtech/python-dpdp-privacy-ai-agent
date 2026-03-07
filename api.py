"""REST API for DPDP Privacy Agent"""

from flask import Flask, request, jsonify
from dpdp_agent import DPDPAgent
import logging
from functools import wraps
import os
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)
agent = DPDPAgent()

# Simple API key authentication
API_KEY = os.environ.get('DPDP_API_KEY', 'dev-key-change-in-production')

# Rate limiting (in-memory, simple implementation)
rate_limit_store = defaultdict(list)
RATE_LIMIT = 100  # requests per minute per IP

def check_rate_limit(ip: str) -> bool:
    """Simple rate limiting"""
    now = datetime.now()
    cutoff = now - timedelta(minutes=1)
    
    # Clean old entries
    rate_limit_store[ip] = [ts for ts in rate_limit_store[ip] if ts > cutoff]
    
    # Check limit
    if len(rate_limit_store[ip]) >= RATE_LIMIT:
        return False
    
    rate_limit_store[ip].append(now)
    return True

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check rate limit
        ip = request.remote_addr
        if not check_rate_limit(ip):
            return jsonify({"error": "Rate limit exceeded"}), 429
        
        # Check API key
        key = request.headers.get('X-API-Key')
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.errorhandler(ValueError)
def handle_validation_error(e):
    return jsonify({"error": str(e)}), 400

@app.errorhandler(Exception)
def handle_error(e):
    logging.error(f"API Error: {e}")
    return jsonify({"error": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})

@app.route('/consent/grant', methods=['POST'])
@require_api_key
def grant_consent():
    data = request.json
    if not data or 'user_id' not in data or 'purpose' not in data:
        return jsonify({"error": "user_id and purpose required"}), 400
    
    agent.grant_consent(
        data['user_id'], 
        data['purpose'], 
        data.get('duration_days')
    )
    return jsonify({"status": "success"}), 200

@app.route('/consent/revoke', methods=['POST'])
@require_api_key
def revoke_consent():
    data = request.json
    if not data or 'user_id' not in data or 'purpose' not in data:
        return jsonify({"error": "user_id and purpose required"}), 400
    
    agent.revoke_consent(data['user_id'], data['purpose'])
    return jsonify({"status": "success"}), 200

@app.route('/data/store', methods=['POST'])
@require_api_key
def store_data():
    data = request.json
    if not data or 'user_id' not in data or 'text' not in data:
        return jsonify({"error": "user_id and text required"}), 400
    
    agent.store_data(
        data['user_id'], 
        data['text'], 
        data.get('retention_days', 365)
    )
    return jsonify({"status": "success"}), 201

@app.route('/data/process', methods=['POST'])
@require_api_key
def process_data():
    data = request.json
    if not data or 'user_id' not in data or 'text' not in data or 'purpose' not in data:
        return jsonify({"error": "user_id, text, and purpose required"}), 400
    
    result = agent.process_data(
        data['user_id'], 
        data['text'], 
        data['purpose']
    )
    return jsonify(result), 200

@app.route('/data/export/<user_id>', methods=['GET'])
@require_api_key
def export_data(user_id):
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    
    data = agent.export_user_data(user_id)
    return jsonify(data), 200

@app.route('/data/erase/<user_id>', methods=['DELETE'])
@require_api_key
def erase_data(user_id):
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    
    agent.right_to_erasure(user_id)
    return jsonify({"status": "success"}), 200

@app.route('/audit/<user_id>', methods=['GET'])
@require_api_key
def audit_report(user_id):
    logs = agent.get_audit_report(user_id)
    return jsonify({"logs": logs}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
