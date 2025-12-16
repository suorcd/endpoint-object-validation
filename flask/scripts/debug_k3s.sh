#!/usr/bin/env bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}==========================================${NC}"
echo -e "${YELLOW}   EOV Flask K3s Debugger${NC}"
echo -e "${YELLOW}==========================================${NC}"

# 1. Check Pod Status
echo -e "\n${GREEN}1. Checking Pod Status...${NC}"
kubectl get pods -l app=flask-eov -o wide
kubectl get pods -l app=eov-flask-tailscale -o wide

# 2. Check Service Endpoints (CRITICAL for 502 errors)
echo -e "\n${GREEN}2. Checking Service Endpoints...${NC}"
echo "If 'ENDPOINTS' is <none>, the Service can't find the Pod (Readiness probe failure)."
kubectl get endpoints eov-flask-service

# 3. Check App Logs (Look for Python errors)
echo -e "\n${GREEN}3. Flask App Logs (Last 50 lines)...${NC}"
echo "Look for 'ImportError', 'SyntaxError', or 'Address already in use'"
kubectl logs -l app=flask-eov --tail=50 --all-containers=true

# 4. Check for Kubernetes Events (Readiness/Liveness failures)
echo -e "\n${GREEN}4. Pod Events (Readiness/Liveness Probe Failures)...${NC}"
# Get the first pod name
POD_NAME=$(kubectl get pods -l app=flask-eov -o jsonpath="{.items[0].metadata.name}")
if [ -n "$POD_NAME" ]; then
    kubectl describe pod "$POD_NAME" | grep -A 20 "Events:"
else
    echo -e "${RED}No pods found with label app=flask-eov${NC}"
fi

# 5. Tailscale Logs (if applicable)
echo -e "\n${GREEN}5. Tailscale Proxy Logs...${NC}"
kubectl logs -l app=eov-flask-tailscale --tail=20 2>/dev/null || echo "Tailscale logs not available or not deployed."

echo -e "\n${YELLOW}==========================================${NC}"
echo -e "${YELLOW}Diagnosis Tips:${NC}"
echo "1. If Logs show 'ImportError', your Dockerfile needs the missing package (check urllib3/retry)."
echo "2. If Endpoints are <none>, the Readiness Probe failed (check Events above)."
echo "3. If Pod status is 'CrashLoopBackOff', the app is exiting immediately on start."
echo -e "${YELLOW}==========================================${NC}"