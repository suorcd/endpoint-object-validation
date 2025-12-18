#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running debug_eov.sh (Version: 1)"
echo "=========================================="

echo ""
echo "--- NAMESPACE JSON (Metadata) ---"
# We look specifically at the metadata to find 'finalizers'
kubectl get namespace eov -o json | jq '.spec, .status' || kubectl get namespace eov -o yaml

echo ""
echo "--- INGRESS JSON ---"
# We suspect the Tailscale ingress might be holding the lock
kubectl get ingress eov-tailscale -n eov -o json | jq '.metadata.finalizers' || kubectl get ingress eov-tailscale -n eov -o yaml