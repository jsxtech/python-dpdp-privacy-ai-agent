"""REST API for DPDP Privacy Agent

Production notes:
- Deploy behind a reverse proxy (nginx/caddy) for TLS termination and CORS headers.
- If calling from browser clients, configure CORS on the reverse proxy or add flask-cors.
- This API is designed for server-to-server use; browser access is not the primary use case.
"""

import hmac
import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from dpdp_agent import DPDPAgent

app = Flask(__name__)

# Load config
config = {}
if os.path.exists('config.json'):
    with open('config.json') as f:
        config = json.load(f)

# Initialize agent with config
agent = DPDPAgent(
    storage_path=config.get('storage_path'),
    config_path='config.json'
)

# API key authentication - refuse to start without it
API_KEY = os.environ.get('DPDP_API_KEY')
if not API_KEY:
    raise RuntimeError(
        "DPDP_API_KEY environment variable is required. "
        "Set it before starting the server."
    )

# Rate limiting (in-memory, thread-safe)
_rate_lock = threading.Lock()
_rate_limit_store: dict = defaultdict(list)
RATE_LIMIT = 100  # requests per minute per IP
_request_counter = 0
_CLEANUP_INTERVAL = 1000

# Uptime tracking
_start_time = time.time()


def _cleanup_rate_limits():
    """Prune stale IPs from the rate limit store to prevent memory leak.
    Must be called with _rate_lock held."""
    now = datetime.now()
    cutoff = now - timedelta(minutes=2)
    stale_ips = [ip for ip, timestamps in _rate_limit_store.items()
                 if not timestamps or timestamps[-1] < cutoff]
    for ip in stale_ips:
        del _rate_limit_store[ip]


def check_rate_limit(ip: str) -> bool:
    """Thread-safe rate limiting with periodic cleanup"""
    global _request_counter

    with _rate_lock:
        _request_counter += 1

        # Periodic cleanup of stale entries
        if _request_counter >= _CLEANUP_INTERVAL:
            _request_counter = 0
            _cleanup_rate_limits()

        now = datetime.now()
        cutoff = now - timedelta(minutes=1)

        # Clean old entries for this IP
        _rate_limit_store[ip] = [ts for ts in _rate_limit_store[ip] if ts > cutoff]

        # Check limit
        if len(_rate_limit_store[ip]) >= RATE_LIMIT:
            return False

        _rate_limit_store[ip].append(now)
        return True


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check rate limit
        ip = request.remote_addr
        if not check_rate_limit(ip):
            return jsonify({"error": "Rate limit exceeded"}), 429

        # Check API key using timing-safe comparison
        key = request.headers.get('X-API-Key', '')
        if not hmac.compare_digest(key, API_KEY):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def require_json(f):
    """Validate that POST/PUT requests have application/json Content-Type and valid JSON body"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        # Ensure the body is valid JSON (request.json returns None for parse errors
        # in some Flask versions, or raises BadRequest in others)
        try:
            if request.json is None:
                return jsonify({"error": "Request body must be valid JSON"}), 400
        except Exception:
            return jsonify({"error": "Request body must be valid JSON"}), 400
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
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "uptime_seconds": round(time.time() - _start_time, 1)
    })


@app.route('/consent/grant', methods=['POST'])
@require_api_key
@require_json
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
@require_json
def revoke_consent():
    data = request.json
    if not data or 'user_id' not in data or 'purpose' not in data:
        return jsonify({"error": "user_id and purpose required"}), 400

    agent.revoke_consent(data['user_id'], data['purpose'])
    return jsonify({"status": "success"}), 200


@app.route('/data/store', methods=['POST'])
@require_api_key
@require_json
def store_data():
    data = request.json
    if not data or 'user_id' not in data or 'text' not in data:
        return jsonify({"error": "user_id and text required"}), 400

    try:
        agent.store_data(
            data['user_id'],
            data['text'],
            data.get('retention_days'),
            data.get('purpose')
        )
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403

    return jsonify({"status": "success"}), 201


@app.route('/data/process', methods=['POST'])
@require_api_key
@require_json
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


@app.route('/data/cleanup', methods=['POST'])
@require_api_key
def cleanup_expired():
    """Delete data past retention period"""
    deleted = agent.delete_expired_data()
    return jsonify({"status": "success", "deleted_count": deleted}), 200


@app.route('/audit/<user_id>', methods=['GET'])
@require_api_key
def audit_report(user_id):
    logs = agent.get_audit_report(user_id)
    return jsonify({"logs": logs}), 200


if __name__ == '__main__':
    api_config = config.get('api', {})
    app.run(
        host=api_config.get('host', '0.0.0.0'),
        port=api_config.get('port', 5000),
        debug=api_config.get('debug', False)
    )
