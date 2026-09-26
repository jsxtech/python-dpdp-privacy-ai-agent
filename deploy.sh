#!/bin/bash

# DPDP Privacy Agent - Production Deployment Script

echo "Starting DPDP Privacy Agent deployment..."

# Validate required environment variables
if [ -z "$DPDP_API_KEY" ]; then
    echo "ERROR: DPDP_API_KEY environment variable is required."
    echo "Set it with: export DPDP_API_KEY=your-secure-api-key"
    exit 1
fi

if [ -z "$DPDP_ENCRYPTION_KEY" ]; then
    echo "ERROR: DPDP_ENCRYPTION_KEY environment variable is required."
    echo "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    exit 1
fi

# Create necessary directories
mkdir -p data logs

# Direct application logs into the logs/ directory (matches mkdir above)
export DPDP_LOG_FILE="${DPDP_LOG_FILE:-logs/dpdp_agent.log}"

# Install dependencies
pip install -r requirements.txt

echo "Environment variables validated."
echo "IMPORTANT: Keep your encryption key secure. Without it, encrypted data cannot be recovered."

# Run API server
echo "Starting API server on port 5000..."
python api.py
