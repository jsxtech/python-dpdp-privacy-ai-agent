# DPDP Privacy AI Agent

Python-based AI agent for Digital Personal Data Protection (DPDP) Act compliance.

## Features

### Core Privacy Functions
- **Data Classification** - Automatically categorizes data as PII, Sensitive, Financial, Health, or General
- **Consent Management** - Grant, revoke, and verify user consent with expiration support
- **Data Anonymization** - Masks emails, phone numbers, Aadhaar, and card numbers
- **Risk Assessment** - Evaluates processing risk levels (Low/Medium/High/Critical)

### DPDP Compliance
- **Right to Erasure** - Complete user data deletion on request
- **Data Portability** - Export all user data in JSON format
- **Purpose Limitation** - Blocks processing without valid consent
- **Data Retention** - Automatic deletion after retention period expires

### Security & Monitoring
- **Audit Logging** - Tracks all data access and consent changes
- **Breach Detection** - Identifies suspicious access patterns
- **Compliance Reports** - Generate audit trails for regulatory review
- **Consent Expiration** - Time-limited consent with auto-revocation

### Production Features
- **Data Encryption** - AES-128 encryption for all stored sensitive data
- **Persistent Storage** - JSON-based state persistence with atomic writes
- **Error Handling** - Comprehensive exception handling and logging
- **REST API** - Flask-based HTTP API with authentication
- **Rate Limiting** - 100 requests/minute per IP address
- **Input Validation** - Length checks and sanitization
- **Configuration** - External config file for deployment settings

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Python Library

```python
from dpdp_agent import DPDPAgent

# Initialize with encryption key
agent = DPDPAgent(encryption_key="your-44-char-base64-key")

# Grant consent
agent.grant_consent("user123", "marketing", duration_days=90)

# Store data (encrypted automatically)
agent.store_data("user123", "Email: user@example.com")

# Process data
result = agent.process_data("user123", "Contact info", "marketing")

# Export user data
data = agent.export_user_data("user123")

# Right to erasure
agent.right_to_erasure("user123")

# Audit report
logs = agent.get_audit_report("user123")
```

### REST API

Start the API server:

```bash
# Set API key (required for authentication)
export DPDP_API_KEY="your-secure-api-key"

# Set encryption key (required for data encryption)
export DPDP_ENCRYPTION_KEY="your-44-char-base64-key"

# Deploy
./deploy.sh
# Or manually: python api.py
```

API Endpoints (all require `X-API-Key` header):

```bash
# Health check (no auth required)
GET /health

# Grant consent
POST /consent/grant
Headers: X-API-Key: your-secure-api-key
{"user_id": "user123", "purpose": "marketing", "duration_days": 90}

# Revoke consent
POST /consent/revoke
Headers: X-API-Key: your-secure-api-key
{"user_id": "user123", "purpose": "marketing"}

# Store data
POST /data/store
Headers: X-API-Key: your-secure-api-key
{"user_id": "user123", "text": "Email: user@example.com"}

# Process data
POST /data/process
Headers: X-API-Key: your-secure-api-key
{"user_id": "user123", "text": "Contact info", "purpose": "marketing"}

# Export user data
GET /data/export/<user_id>
Headers: X-API-Key: your-secure-api-key

# Right to erasure
DELETE /data/erase/<user_id>
Headers: X-API-Key: your-secure-api-key

# Audit report
GET /audit/<user_id>
Headers: X-API-Key: your-secure-api-key
```

## Configuration

Edit `config.json`:

```json
{
  "storage_path": "data/dpdp_storage.json",
  "breach_threshold": 5,
  "default_retention_days": 365,
  "log_level": "INFO",
  "api": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false
  }
}
```

## Data Categories

- **PII** - Email, phone, Aadhaar numbers
- **Financial** - Credit/debit card numbers
- **Health** - Medical conditions
- **Sensitive** - Protected personal data
- **General** - Non-sensitive information

## Security Features

- **Encryption**: All sensitive data encrypted at rest using Fernet (AES-128)
- **Authentication**: API key-based authentication for all endpoints
- **Rate Limiting**: 100 requests per minute per IP address
- **Input Validation**: Length limits and sanitization on all inputs
- **Atomic Writes**: Prevents data corruption during save operations
- **Audit Trail**: Complete logging of all data operations

## Production Deployment

1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variables:
   ```bash
   export DPDP_API_KEY="your-secure-api-key"
   export DPDP_ENCRYPTION_KEY="your-44-char-base64-key"
   ```
3. Configure settings in `config.json`
4. Run deployment script: `./deploy.sh`
5. API will be available at `http://localhost:5000`

**IMPORTANT**: Save your encryption key securely. Without it, encrypted data cannot be recovered.

## Logging

Logs are written to:
- Console (stdout)
- A log file (default `dpdp_agent.log` in the working directory)

Set `DPDP_LOG_FILE` to change the log path, e.g. `export DPDP_LOG_FILE=logs/dpdp_agent.log`.
The deployment script sets this to `logs/dpdp_agent.log` automatically.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DPDP_API_KEY` | Yes | API key for authenticating requests (`X-API-Key` header). |
| `DPDP_ENCRYPTION_KEY` | Yes | Encryption key. A 44-char base64 Fernet key is used directly; any other value is treated as a passphrase and a key is derived via PBKDF2. |
| `DPDP_TRUSTED_PROXIES` | No (default `1`) | Number of trusted reverse-proxy hops. Enables `ProxyFix` so rate limiting keys on the real client IP via `X-Forwarded-For`. Set to `0` when not behind a proxy. |
| `DPDP_LOG_FILE` | No | Path to the log file. Defaults to `dpdp_agent.log`. |

**Encryption key note:** Prefer a proper 44-char Fernet key in production. When a passphrase is
used instead, a random per-deployment salt is generated and stored next to the data file (e.g.
`data/dpdp_storage.salt`). Back up this salt file — without it, passphrase-derived data cannot be
decrypted. Existing deployments that predate the salt file fall back to a legacy salt for
backward compatibility.

## Testing

```bash
pip install pytest
pytest
```

## Running Behind a Reverse Proxy

Rate limiting is keyed on the client IP. When deployed behind nginx/caddy, set
`DPDP_TRUSTED_PROXIES` to the number of proxy hops so the real client IP is read from
`X-Forwarded-For`. Only enable this when you control the proxy, as forwarded headers can be
spoofed by untrusted clients.

## License

MIT


