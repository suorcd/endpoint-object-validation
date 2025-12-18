#!/usr/bin/env bash
# Version: 1
echo "=========================================="
echo "Running hard_reset_proxy.sh (Version: 1)"
echo "=========================================="

NAMESPACE="tailscale"
# We know the pod name from your previous debug logs
POD_NAME="ts-eov-tailscale-fn46c-0"
# The state secret usually has the same name as the StatefulSet (pod name minus the -0)
SECRET_NAME="ts-eov-tailscale-fn46c"

echo "Targeting Proxy: $POD_NAME"

echo ""
echo "1. Deleting State Secret (Forces re-authentication)..."
# This deletes the "disk" where Tailscale stores its login state.
# The Operator will recreate it with a fresh Auth Key.
kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE" --ignore-not-found

echo ""
echo "2. Deleting Proxy Pod (Forces restart)..."
kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found

echo ""
echo "3. Waiting for Pod to recreate..."
# Wait for the StatefulSet controller to bring it back
sleep 5
kubectl wait --for=condition=Ready pod/"$POD_NAME" -n "$NAMESPACE" --timeout=120s

echo ""
echo "4. Checking Logs:"
kubectl logs "$POD_NAME" -n "$NAMESPACE" --tail=20
