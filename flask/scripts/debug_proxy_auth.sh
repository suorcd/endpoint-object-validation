#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running debug_proxy_auth.sh (Version: 1)"
echo "=========================================="

PROXY_POD="ts-eov-tailscale-fn46c-0"
NAMESPACE="tailscale"

echo "1. Checking Proxy Pod Environment Variables..."
# Check if TS_AUTHKEY or similar is set
kubectl get pod "$PROXY_POD" -n "$NAMESPACE" -o jsonpath='{range .spec.containers[*].env[*]}{.name}{"="}{.value}{"\n"}{end}' | grep -i "AUTH" || echo "No AUTH env vars found."

echo ""
echo "2. Checking for Auth Secret Mounts..."
# Check if a secret is mounted
kubectl get pod "$PROXY_POD" -n "$NAMESPACE" -o jsonpath='{range .spec.containers[*].volumeMounts[*]}{.name}{" -> "}{.mountPath}{"\n"}{end}'

echo ""
echo "3. Checking Tailscale ACL Tags..."
echo "The Operator needs permission to tag devices."
echo "Ensure your Tailscale Access Controls (https://login.tailscale.com/admin/acls) contain this section:"
echo ""
echo "  \"tagOwners\": {"
echo "    \"tag:k8s-operator\": [],"
echo "    \"tag:k8s\": [\"tag:k8s-operator\"],"
echo "  }"
