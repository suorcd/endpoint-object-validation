#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running watch_ingress.sh (Version: 1)"
echo "=========================================="

echo "Monitoring Ingress 'eov-tailscale' for Address assignment..."
echo "Look for the 'ADDRESS' column to change from empty to a DNS name or IP."
echo "(Press Ctrl+C to exit once you see the address)"
echo ""

kubectl get ingress eov-tailscale -n eov -w
