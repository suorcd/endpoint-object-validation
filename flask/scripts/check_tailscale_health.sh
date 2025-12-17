#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running check_tailscale_health.sh (Version: 1)"
echo "=========================================="

echo "1. Checking all resources in 'tailscale' namespace..."
kubectl get all -n tailscale

echo ""
echo "2. Fetching recent logs from the Tailscale Operator..."
# We attempt to find the pod name dynamically without using jq
POD_NAME=$(kubectl get pods -n tailscale --no-headers | grep -v "Terminating" | head -n 1 | awk '{print $1}')

if [ -z "$POD_NAME" ]; then
    echo "ERROR: No running pods found in 'tailscale' namespace!"
else
    echo "Found Pod: $POD_NAME"
    echo "--- LOGS START ---"
    kubectl logs "$POD_NAME" -n tailscale --tail=20
    echo "--- LOGS END ---"
fi