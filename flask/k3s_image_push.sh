#!/usr/bin/env bash
set -e

# Configuration
IMAGE_NAME="eov-flask:latest"

# Optional: load overrides from .env next to this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
fi

# List all your node IPs/hosts (k3s server and agents). Override via NODE_IPS env var.
# Example: export NODE_IPS="192.0.2.10 192.0.2.11"
NODE_IPS_STRING=${NODE_IPS:-"192.0.2.10 192.0.2.11"}
IFS=' ' read -r -a NODE_IPS_ARRAY <<< "$NODE_IPS_STRING"

# Change this to your SSH user for the nodes (can override via SSH_USER env var)
SSH_USER=${SSH_USER:-"root"}

echo "=========================================="
echo "   K3s Image Mover (Multi-Node)"
echo "=========================================="

echo "1. Saving image from Docker..."
docker save "$IMAGE_NAME" | zstd -o eov-flask.tar.zst

# Loop through all nodes
for IP in "${NODE_IPS_ARRAY[@]}"; do
    echo ""
    echo "------------------------------------------"
    echo "Processing Node: $IP"
    echo "------------------------------------------"
    
    echo "2. Copying compressed image to $IP..."
    # Note: You might need to type your password here
    scp eov-flask.tar.zst "${SSH_USER}@${IP}:/tmp/eov-flask.tar.zst"

    echo "3. Importing image into K3s containerd on $IP..."
    ssh "${SSH_USER}@${IP}" "zstd -d /tmp/eov-flask.tar.zst -o /tmp/eov-flask.tar && sudo k3s ctr images import /tmp/eov-flask.tar && rm /tmp/eov-flask.tar"

    echo "4. Cleaning up remote compressed file on $IP..."
    ssh "${SSH_USER}@${IP}" "rm -f /tmp/eov-flask.tar.zst"
done

echo ""
echo "5. Cleaning up local file..."
rm eov-flask.tar.zst

echo "=========================================="
echo "Success! The image is now on all nodes."
echo "You can now run ./deploy.sh"
echo "=========================================="