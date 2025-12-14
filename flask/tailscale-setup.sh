#!/usr/bin/env bash

# Tailscale Setup Script for Kubernetes
# This script configures Tailscale integration for the eov-flask service

set -e

echo "=========================================="
echo "Tailscale Kubernetes Setup"
echo "=========================================="

# Check if kubectl is configured
if ! kubectl cluster-info &> /dev/null; then
    echo "ERROR: kubectl not configured or cluster unreachable"
    exit 1
fi

echo "✓ Cluster is reachable"

# Create namespace if it doesn't exist
kubectl create namespace eov --dry-run=client -o yaml | kubectl apply -f -

# Step 1: Get Tailscale auth key
echo ""
echo "Step 1: Tailscale Authentication"
echo "To get your auth key:"
echo "  1. Go to https://login.tailscale.com/admin/settings/keys"
echo "  2. Generate a new Auth key (reusable recommended)"
echo ""
read -p "Enter your Tailscale Auth Key: " AUTH_KEY

if [ -z "$AUTH_KEY" ]; then
    echo "ERROR: Auth key cannot be empty"
    exit 1
fi

# Step 2: Get Tailnet Name
echo ""
echo "Step 2: Tailnet Name Configuration"
echo "We need your Tailnet name to configure the internal proxy."
echo "  1. Go to https://login.tailscale.com/admin/dns"
echo "  2. Copy the 'Tailnet name' at the top (e.g., panda-beta.ts.net)"
echo ""
read -p "Enter your Tailnet Name: " TAILNET_NAME

if [ -z "$TAILNET_NAME" ]; then
    echo "ERROR: Tailnet name cannot be empty"
    exit 1
fi

# Step 3: Create the Tailscale secret
echo ""
echo "Step 3: Creating Tailscale authentication secret..."

kubectl create secret generic tailscale-auth \
  --from-literal=auth-key="$AUTH_KEY" \
  -n eov \
  --dry-run=client \
  -o yaml | kubectl apply -f -

echo "✓ Secret created/updated"

# Step 4: Apply Tailscale configuration with substitution
echo ""
echo "Step 4: Applying Tailscale deployment configuration..."

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Read the template and replace the placeholder with the actual tailnet name
# We use | as delimiter for sed to avoid issues with dots in domain names
sed "s|PLACEHOLDER_TAILNET_NAME|$TAILNET_NAME|g" "$SCRIPT_DIR/tailscale-deployment.yaml" | kubectl apply -f -

echo "✓ Tailscale configuration applied with host: eov-flask.$TAILNET_NAME"

# Step 5: Wait for Tailscale pod to be ready
echo ""
echo "Step 5: Waiting for Tailscale pod to be ready..."

kubectl rollout status deployment/eov-flask-tailscale -n eov --timeout=2m

echo "✓ Tailscale is ready"

# Step 7: Get device info
echo ""
echo "=========================================="
echo "Tailscale Setup Complete!"
echo "=========================================="
echo ""
echo "Device registered on your tailnet as: eov"
echo ""
echo "Your service should now be accessible via:"
echo "  https://eov.$TAILNET_NAME"
echo ""
echo "To verify:"
echo "  kubectl logs -l app=eov-flask-tailscale -n eov | grep -i 'serve'"