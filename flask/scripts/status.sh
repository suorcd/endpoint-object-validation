#!/usr/bin/env bash

# Status check script - view what's running on your cluster

echo "=========================================="
echo "Kubernetes Cluster Status Report"
echo "=========================================="
echo ""

echo "NODES:"
kubectl get nodes -o wide
echo ""

echo "NAMESPACES:"
kubectl get namespaces
echo ""

echo "SERVICES (with port mappings):"
kubectl get services -n eov -o wide
echo ""

echo "DEPLOYMENTS:"
kubectl get deployments -n eov -o wide
echo ""

echo "PODS:"
kubectl get pods -n eov -o wide
echo ""

echo "INGRESS:"
kubectl get ingress -n eov -o wide
echo ""

echo "CONFIGMAPS:"
kubectl get configmaps -n eov
echo ""

echo "Port 80 Status:"
echo "Services listening on port 80:"
# Fixed JSONPath to correctly handle the list comparison
kubectl get services -n eov -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.ports[?(@.port==80)].port}{"\n"}{end}' | grep "80" || echo "None found"