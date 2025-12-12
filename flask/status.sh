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
kubectl get services -n default -o wide
echo ""

echo "DEPLOYMENTS:"
kubectl get deployments -n default -o wide
echo ""

echo "PODS:"
kubectl get pods -n default -o wide
echo ""

echo "INGRESS:"
kubectl get ingress -n default -o wide
echo ""

echo "CONFIGMAPS:"
kubectl get configmaps -n default
echo ""

echo "Port 80 Status:"
echo "Services listening on port 80:"
kubectl get services -n default -o jsonpath='{range .items[?(@.spec.ports[*].port==80)]}{.metadata.name}{"\t"}{.metadata.namespace}{"\n"}{end}'
