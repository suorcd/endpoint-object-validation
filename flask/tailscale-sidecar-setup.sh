#!/usr/bin/env bash

# Tailscale Setup Script for Kubernetes
# This script configures Tailscale integration for the eov-flask service

set -e

# Parse command line arguments
DELETE_MODE=false
if [ "$1" = "--delete" ]; then
    DELETE_MODE=true
fi

# Delete mode - cleanup everything
if [ "$DELETE_MODE" = true ]; then
    echo "=========================================="
    echo "Tailscale Kubernetes Cleanup"
    echo "=========================================="
    
    # Check if kubectl is configured
    if ! kubectl cluster-info &> /dev/null; then
        echo "ERROR: kubectl not configured or cluster unreachable"
        exit 1
    fi
    
    echo "✓ Cluster is reachable"
    echo ""
    echo "This will delete:"
    echo "  - Tailscale deployment (eov-flask-tailscale)"
    echo "  - Tailscale authentication secret (tailscale-auth)"
    echo "  - Service account and related resources"
    echo ""
    read -p "Are you sure you want to proceed? (yes/no): " CONFIRM
    
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled"
        exit 0
    fi
    
    echo ""
    echo "Deleting Tailscale deployment..."
    kubectl delete deployment eov-flask-tailscale -n eov 2>/dev/null || echo "  (deployment not found)"
    
    echo "Deleting Tailscale secret..."
    kubectl delete secret tailscale-auth -n eov 2>/dev/null || echo "  (secret not found)"
    
    echo "Deleting service account..."
    kubectl delete serviceaccount tailscale -n eov 2>/dev/null || echo "  (service account not found)"
    
    echo "Deleting role..."
    kubectl delete role tailscale -n eov 2>/dev/null || echo "  (role not found)"
    
    echo "Deleting role binding..."
    kubectl delete rolebinding tailscale -n eov 2>/dev/null || echo "  (role binding not found)"
    
    echo ""
    echo "=========================================="
    echo "Tailscale Cleanup Complete!"
    echo "=========================================="
    exit 0
fi

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

echo "✓ Tailscale configuration applied with host: eov.$TAILNET_NAME"

# Step 5: Force rollout restart to pick up new config
echo ""
echo "Step 5: Restarting Tailscale pod to apply new config..."
kubectl rollout restart deployment/eov-flask-tailscale -n eov

# Step 6: Wait for Tailscale pod to be ready
echo ""
echo "Step 6: Waiting for Tailscale pod to be ready..."

if kubectl rollout status deployment/eov-flask-tailscale -n eov --timeout=30s; then
    echo "✓ Tailscale is ready"
else
    echo "Rollout failed, checking for auth key issues..."
    # Check logs for invalid key error
    if kubectl logs -l app=eov-flask-tailscale -n eov --tail=20 2>/dev/null | grep -q "invalid key"; then
        echo "ERROR: The provided Tailscale auth key is invalid or expired."
        echo "Please generate a new auth key from https://login.tailscale.com/admin/settings/keys"
        exit 1
    else
        echo "ERROR: Tailscale pod failed to start for an unknown reason."
        echo "Check pod logs with: kubectl logs -l app=eov-flask-tailscale -n eov"
        exit 1
    fi
fi

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