#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running debug_proxy_pod.sh (Version: 1)"
echo "=========================================="

# We identify the pod name based on the stuck StatefulSet found in the previous step
POD_NAME="ts-eov-tailscale-fn46c-0"
NAMESPACE="tailscale"

echo "1. Pod Status for '$POD_NAME'..."
kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o wide

echo ""
echo "2. Pod Events (Scheduling/Image issues)..."
kubectl describe pod "$POD_NAME" -n "$NAMESPACE" | grep -A 20 "Events:"

echo ""
echo "3. Pod Logs (Application issues)..."
echo "--- Tail (Last 50 lines) ---"
kubectl logs "$POD_NAME" -n "$NAMESPACE" --tail=50

echo ""
echo "4. Checking capabilities/security..."
# Sometimes these pods fail because they need NET_ADMIN capabilities that are blocked
kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext}'
