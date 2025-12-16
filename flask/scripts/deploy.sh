#!/usr/bin/env bash

# Kubernetes Cluster Deployment Script
# k3s server and agents (set your hosts via .env or environment variables)

set -e

# Parse arguments
TAILSCALE=false
TS_OPERATOR=false
DELETE_MODE=false
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --tailscale)
            TAILSCALE=true
            shift
            ;;
        --ts-operator)
            TS_OPERATOR=true
            shift
            ;;
        --delete)
            DELETE_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--tailscale|--ts-operator] [--delete]"
            echo "  --tailscale    Deploy with separate Tailscale proxy container"
            echo "  --ts-operator  Deploy with Tailscale operator (requires operator installed)"
            echo "  --delete       Remove all eov resources and namespace"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Load .env if it exists
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    source "$SCRIPT_DIR/.env"
fi

# Check if kubectl is configured
if ! kubectl cluster-info &> /dev/null; then
    echo "ERROR: kubectl not configured or cluster unreachable"
    exit 1
fi

# Handle delete mode
if [ "$DELETE_MODE" = true ]; then
    echo "========================================="
    echo "Cleaning up eov resources"
    echo "========================================="
    echo "Removing deployments, services, ingress, and namespace..."
    kubectl delete namespace eov --ignore-not-found
    echo "✓ eov namespace and all resources removed"
    exit 0
fi

echo "✓ Cluster is reachable"

# Set default image name if not provided in .env
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/suorcd/eov-flask:latest}"

echo "=========================================="
echo "Kubernetes Cluster Setup"
echo "=========================================="
echo "Target Image: $IMAGE_NAME"

if $TS_OPERATOR; then
    echo "Tailscale Operator deployment enabled"
elif $TAILSCALE; then
    echo "Tailscale proxy deployment enabled"
else
    echo "Tailscale disabled (use --tailscale or --ts-operator to enable)"
fi

# Create namespace if it doesn't exist
kubectl create namespace eov --dry-run=client -o yaml | kubectl apply -f -

# Step 0: Rebuild and push the Docker image
echo ""
echo "Step 0: Building and pushing Docker image..."
DOCKER_CONTEXT="$SCRIPT_DIR/.."
if [[ ! -f "$DOCKER_CONTEXT/Dockerfile" ]]; then
    echo "ERROR: Dockerfile not found at $DOCKER_CONTEXT/Dockerfile"
    exit 1
fi

docker build -t "$IMAGE_NAME" "$DOCKER_CONTEXT"
docker push "$IMAGE_NAME"
echo "✓ Docker image built and pushed"

# Step 1: Apply configuration
echo ""
echo "Step 1: Applying configuration..."


# Apply YAML files with a fallback for immutable selector errors
# (deployment selectors are immutable; if they changed, delete/recreate the deployment)
set +e

if $TS_OPERATOR; then
    # Use ts-operator manifest (includes deployment + service with Tailscale annotations)
    sed "s|\${IMAGE_NAME}|$IMAGE_NAME|g" "$SCRIPT_DIR/../manifests/eov-ts-operator.yaml" | kubectl apply -f -
    APPLY_STATUS=$?
    if [[ $APPLY_STATUS -ne 0 ]]; then
        echo "Apply failed (likely immutable selector). Deleting deployment/eov and retrying..."
        kubectl delete deployment/eov --ignore-not-found
        sed "s|\${IMAGE_NAME}|$IMAGE_NAME|g" "$SCRIPT_DIR/../manifests/eov-ts-operator.yaml" | kubectl apply -f - || exit 1
    fi
else
    # Use standard deployment manifest (includes ingress)
    sed "s|\${IMAGE_NAME}|$IMAGE_NAME|g" "$SCRIPT_DIR/../manifests/eov.yaml" | kubectl apply -f -
    APPLY_STATUS=$?
    if [[ $APPLY_STATUS -ne 0 ]]; then
        echo "Apply failed (likely immutable selector). Deleting deployment/eov and retrying..."
        kubectl delete deployment/eov --ignore-not-found
        sed "s|\${IMAGE_NAME}|$IMAGE_NAME|g" "$SCRIPT_DIR/../manifests/eov.yaml" | kubectl apply -f - || exit 1
    fi
    
    # Apply separate tailscale proxy if --tailscale flag is used
    if $TAILSCALE; then
        kubectl apply -f "$SCRIPT_DIR/../manifests/tailscale-deployment.yaml"
    fi
fi

echo "✓ Configuration applied"

# Step 2: Force rollout restart to pick up new image
echo ""
echo "Step 2: Forcing deployment rollout with new image..."

kubectl rollout restart deployment/eov -n eov
if $TAILSCALE; then
    kubectl rollout restart deployment/eov-flask-tailscale -n eov
fi

echo "✓ Rollout restarted"

# Step 3: Wait for rollout
echo ""
echo "Step 3: Waiting for deployment rollout..."

kubectl rollout status deployment/eov -n eov --timeout=5m
if $TAILSCALE; then
    kubectl rollout status deployment/eov-tailscale -n eov --timeout=5m
fi

echo "✓ Deployments are ready"

# Step 4: Status
echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
kubectl get services -n eov
echo ""
kubectl get ingress -n eov
echo ""
echo "Access via:"
if [ -n "${HOST:-}" ]; then
    echo "  LAN:       http://${HOST}"
elif [ -n "${INGRESS_HOST:-}" ]; then
    echo "  LAN:       http://${INGRESS_HOST}/  (Ingress IP)"
fi
if $TS_OPERATOR; then
    echo "  Tailscale: https://eov.... (HTTPS only)"
fi