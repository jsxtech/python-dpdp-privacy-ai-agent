#!/bin/bash

# DPDP Privacy Agent - Production Deployment Script

echo "Starting DPDP Privacy Agent deployment..."

# Create necessary directories
mkdir -p data logs

# Install dependencies
pip install -r requirements.txt

# Set API key (change this in production!)
export DPDP_API_KEY="${DPDP_API_KEY:-dev-key-change-in-production}"

# Set encryption key (IMPORTANT: Save this key securely!)
if [ -z "$DPDP_ENCRYPTION_KEY" ]; then
    echo "WARNING: No DPDP_ENCRYPTION_KEY set. Generating new key..."
    echo "IMPORTANT: Save the encryption key from logs for data recovery!"
fi

echo "API Key: $DPDP_API_KEY"
echo "IMPORTANT: Set DPDP_API_KEY and DPDP_ENCRYPTION_KEY environment variables in production!"

# Run API server
echo "Starting API server on port 5000..."
python api.py
