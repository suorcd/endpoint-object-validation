#!/usr/bin/env bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=========================================="
echo "EOV Connectivity Debugger"
echo -e "==========================================${NC}"

# 1. Identify Pods
TS_POD=$(kubectl get pods -l app=eov-flask-tailscale -o jsonpath="{.items[0].metadata.name}")
FLASK_SVC="eov-flask-service.default.svc.cluster.local"

if [ -z "$TS_POD" ]; then
    echo -e "${RED}Error: Tailscale pod not found.${NC}"
    exit 1
fi

echo "Tailscale Pod: $TS_POD"
echo "Target Service: $FLASK_SVC"

# 2. Check Tailscale Config
echo -e "\n${GREEN}[1] Checking Tailscale Serve Config inside Pod...${NC}"
# We check the mounted config file to see if variables were resolved
kubectl exec "$TS_POD" -- cat /config/serve.json
echo -e "\n${YELLOW}NOTE: If you see '\${TS_CERT_DOMAIN}' above, Kubernetes did NOT replace the variable.${NC}"
echo -e "${YELLOW}      This will cause 502s because the hostname literal doesn't match.${NC}"

# 3. Test Internal Connectivity
echo -e "\n${GREEN}[2] Testing Internal Connectivity (Tailscale -> Flask)...${NC}"
echo "Running wget from inside the Tailscale pod to the Flask service..."
kubectl exec "$TS_POD" -- wget -qO- --timeout=5 "http://$FLASK_SVC:80/" > /dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}SUCCESS: Tailscale pod can reach Flask service.${NC}"
else
    echo -e "${RED}FAILURE: Tailscale pod CANNOT reach Flask service.${NC}"
    echo "This implies a K3s networking/DNS issue or the Flask app is down."
fi

# 4. Tailscale Logs
echo -e "\n${GREEN}[3] Recent Tailscale Logs (Look for '502' or 'dial' errors)...${NC}"
kubectl logs "$TS_POD" --tail=20

echo -e "\n${YELLOW}==========================================${NC}"