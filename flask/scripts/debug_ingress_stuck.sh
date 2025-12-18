#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running debug_ingress_stuck.sh (Version: 1)"
echo "=========================================="

echo "1. Describing Ingress 'eov-tailscale' (Checking for Events)..."
echo "Look for 'Normal' or 'Warning' lines at the bottom:"
kubectl describe ingress eov-tailscale -n eov | grep -A 20 "Events:"

echo ""
echo "2. Checking for created StatefulSets in 'tailscale'..."
# The operator uses StatefulSets to manage proxies
kubectl get statefulsets -n tailscale

echo ""
echo "3. Checking for any Services in 'tailscale'..."
kubectl get services -n tailscale

echo ""
echo "4. Unfiltered Operator Logs (Last 50 lines)..."
# We need to see if it retried after the lock error
kubectl logs -n tailscale -l app=operator --tail=50
