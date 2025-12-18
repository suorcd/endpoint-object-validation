#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running debug_proxies.sh (Version: 1)"
echo "=========================================="

echo "1. Checking for Tailscale Proxy Pods..."
# The operator creates pods named like 'ts-<ingress-name>-<random>'
kubectl get pods -n tailscale -l app.kubernetes.io/name=proxy -o wide

echo ""
echo "2. Checking for 'Pending' or 'CrashLoop' Proxies..."
# We want to see if any proxy is stuck
kubectl get pods -n tailscale --field-selector=status.phase!=Running

echo ""
echo "3. Operator Logs (Filtering for 'error' or '403')..."
# Look for permission errors (ACLs) preventing device creation
kubectl logs -n tailscale -l app=operator --tail=100 | grep -iE "error|forbidden|403|fail" | tail -n 20

