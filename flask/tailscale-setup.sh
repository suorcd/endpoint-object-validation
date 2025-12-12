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

# Step 1: Get Tailscale auth key
echo ""
echo "Step 1: Tailscale Authentication"
echo "To get your auth key:"
echo "  1. Go to https://login.tailscale.com/"
echo "  2. Navigate to Settings > Keys"
echo "  3. Generate a new Auth key (reusable recommended)"
echo ""
read -p "Enter your Tailscale Auth Key: " AUTH_KEY

if [ -z "$AUTH_KEY" ]; then
    echo "ERROR: Auth key cannot be empty"
    exit 1
fi

# Step 2: Create the Tailscale secret
echo ""
echo "Step 2: Creating Tailscale authentication secret..."

kubectl create secret generic tailscale-auth \
  --from-literal=auth-key="$AUTH_KEY" \
  -n default \
  --dry-run=client \
  -o yaml | kubectl apply -f -

echo "✓ Secret created/updated"

# Step 3: Apply Tailscale configuration
echo ""
echo "Step 3: Applying Tailscale deployment configuration..."

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

kubectl apply -f "$SCRIPT_DIR/tailscale-deployment.yaml"

echo "✓ Tailscale configuration applied"

# Step 4: Wait for Tailscale pod to be ready
echo ""
echo "Step 4: Waiting for Tailscale pod to be ready..."

kubectl rollout status deployment/eov-flask-tailscale -n default --timeout=2m

echo "✓ Tailscale is ready"

# Step 5: Get device info
echo ""
echo "=========================================="
echo "Tailscale Setup Complete!"
echo "=========================================="
echo ""
echo "Device registered on your tailnet as: eov-flask"
echo ""
echo "To verify:"
kubectl describe pod -l app=eov-flask-tailscale -n default | grep -A 5 "Environment:"
echo ""
echo "Your service is now accessible via:"
echo "  https://eov-flask.tailnet-name.ts.net"
echo ""
echo "To get the Tailscale IP address:"
echo "  kubectl logs -l app=eov-flask-tailscale -n default | grep -i 'ipv4'"
