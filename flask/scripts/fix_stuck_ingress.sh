#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running fix_stuck_ingress.sh (Version: 1)"
echo "=========================================="

echo "1. Patching Ingress 'eov-tailscale' to remove finalizers..."
# We use 'merge' patching to set the finalizers list to empty (null)
kubectl patch ingress eov-tailscale -n eov --type=merge -p '{"metadata":{"finalizers":null}}'

echo ""
echo "2. Waiting 5 seconds for Kubernetes garbage collection..."
sleep 5

echo ""
echo "3. Checking if Namespace 'eov' still exists..."
kubectl get namespace eov