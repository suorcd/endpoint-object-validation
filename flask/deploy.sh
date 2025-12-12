#!/usr/bin/env bash

# Kubernetes Cluster Deployment Script
# k3s server and agents (set your hosts via .env or environment variables)

set -e

# Parse arguments
TAILSCALE=false
if [[ "$1" == "--tailscale" ]]; then
    TAILSCALE=true
fi

echo "=========================================="
echo "Kubernetes Cluster Setup"
echo "=========================================="
if $TAILSCALE; then
    echo "Tailscale deployment enabled"
else
    echo "Tailscale deployment disabled (use --tailscale to enable)"
fi

# Check if kubectl is configured
if ! kubectl cluster-info &> /dev/null; then
    echo "ERROR: kubectl not configured or cluster unreachable"
    exit 1
fi

echo "✓ Cluster is reachable"

# Step 0: Rebuild and push the Docker image
echo ""
echo "Step 0: Building and pushing Docker image..."

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

docker build -t gitea.ser.ink/ser/eov-flask:latest .
docker push gitea.ser.ink/ser/eov-flask:latest
echo "✓ Docker image built and pushed"

# Step 1: Apply configuration (No deletion needed!)
# Kubernetes 'apply' is declarative and handles updates automatically.
echo ""
echo "Step 1: Applying configuration..."

# Apply YAML files
kubectl apply -f "$SCRIPT_DIR/eov-flask-deployment.yaml"
kubectl apply -f "$SCRIPT_DIR/eov-flask-ingress.yaml"
if $TAILSCALE; then
    kubectl apply -f "$SCRIPT_DIR/tailscale-deployment.yaml"
fi

echo "✓ Configuration applied"

# Step 2: Force rollout restart to pick up new image
echo ""
echo "Step 2: Forcing deployment rollout with new image..."

kubectl rollout restart deployment/eov-flask -n default
if $TAILSCALE; then
    kubectl rollout restart deployment/eov-flask-tailscale -n default
fi

echo "✓ Rollout restarted"

# Step 3: Wait for rollout
echo ""
echo "Step 3: Waiting for deployment rollout..."

kubectl rollout status deployment/eov-flask -n default --timeout=5m
if $TAILSCALE; then
    kubectl rollout status deployment/eov-flask-tailscale -n default --timeout=5m
fi

echo "✓ Deployments are ready"

# Step 4: Status
echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
kubectl get services -n default
echo ""
kubectl get ingress -n default