#!/usr/bin/env bash
echo "=========================================="
echo "Running nudge_proxies.sh"
echo "=========================================="

echo "1. Deleting the stuck proxy pods..."
# This forces the StatefulSet to recreate them. 
# The Operator will then try to generate a NEW auth key.
# Now that ACLs are fixed, this key generation should succeed.
kubectl delete pods -n tailscale -l app.kubernetes.io/name=proxy

echo ""
echo "2. Watching for the new pods..."
echo "Waiting 10s..."
sleep 10
kubectl get pods -n tailscale -l app.kubernetes.io/name=proxy -w
