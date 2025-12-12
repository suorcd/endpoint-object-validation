# Kubernetes Cluster Deployment Guide

## Overview
Once in the Nix development shell:
```bash
# Navigate to flask directory
cd flask

# Run Flask development server
flask --app app run --host=0.0.0.0 --port=5000

# Or with hot reload for development
flask --app app run --host=0.0.0.0 --port=5000 --debug
```

Access the application at `http://localhost:5000`

## Files Included
- `eov-flask-deployment.yaml` - Flask application with multiple routes
- `eov-flask-ingress.yaml` - Ingress controller configuration
- `tailscale-deployment.yaml` - Tailscale integration configuration
- `deploy.sh` - Automated deployment script
- `tailscale-setup.sh` - Tailscale integration setup script
- `status.sh` - Check cluster status
- `eov.sh` - Endpoint object validation bash script (reference implementation)

## Deployment Steps

### Option 1: Automated Deployment (Recommended)
```bash
# Step 1: Build Docker image
docker build -t eov-flask:latest .

# Step 2: Push image to K3s nodes
chmod +x k3s_image_push.sh
./k3s_image_push.sh

# Step 3: Deploy to Kubernetes cluster
chmod +x deploy.sh
./deploy.sh
```

### Option 2: Add Tailscale Integration (Optional)
```bash
# After completing Option 1, add Tailscale:
chmod +x tailscale-setup.sh
./tailscale-setup.sh
```

This will:
- Prompt for your Tailscale auth key
- Deploy the Tailscale proxy container
- Register your service on your tailnet
- Provide a Tailscale DNS name for access

### Option 3: Manual Deployment
```bash
# Step 1: Build Docker image
# Or with hot reload for development

# Step 2: Save and push image to nodes
flask --app app run --host=0.0.0.0 --port=5000 --debug
# For each node ($SERVER_NODE_HOST and $WORKER_NODE_HOST):
scp eov-flask.tar root@<NODE_IP>:/tmp/eov-flask.tar
ssh root@<NODE_IP> "sudo k3s ctr images import /tmp/eov-flask.tar && rm /tmp/eov-flask.tar"
rm eov-flask.tar

# Step 3: Verify kubectl is configured
kubectl cluster-info

# Step 4: Apply configuration to Kubernetes
kubectl apply -f eov-flask-deployment.yaml
kubectl apply -f eov-flask-ingress.yaml

# Step 5: Wait for deployments to be ready
kubectl rollout status deployment/eov-flask -n default --timeout=5m

# Step 6: Verify deployment
kubectl get services -n default
kubectl get ingress -n default
```
```

Access the application at `http://localhost:5000`

## Files Included
- `eov-flask-deployment.yaml` - Flask application with multiple routes
- `eov-flask-ingress.yaml` - Ingress controller configuration
- `tailscale-deployment.yaml` - Tailscale integration configuration
- `deploy.sh` - Automated deployment script
- `tailscale-setup.sh` - Tailscale integration setup script
- `status.sh` - Check cluster status
- `eov.sh` - Endpoint object validation bash script (reference implementation)

## Deployment Steps
kubectl get services -n default
kubectl get ingress -n default
```bash
 **https://eov-flask.tailnet-name.ts.net** (replace `tailnet-name` with your actual Tailscale domain)
docker build -t eov-flask:latest .
kubectl get pods -l app=eov-flask-tailscale
kubectl logs -l app=eov-flask-tailscale
kubectl rollout restart deployment/eov-flask-tailscale
chmod +x deploy.sh
kubectl delete -f eov-flask-deployment.yaml
kubectl delete -f eov-flask-ingress.yaml
### Option 2: Add Tailscale Integration (Optional)
 **eov-flask** - 2 replicas of Flask application
# After completing Option 1, add Tailscale:
./tailscale-setup.sh
- Prompt for your Tailscale auth key
# Step 1: Build Docker image
docker build -t eov-flask:latest .

# Step 2: Save and push image to nodes
docker save eov-flask:latest -o eov-flask.tar
# For each node ($SERVER_NODE_HOST and $WORKER_NODE_HOST):
scp eov-flask.tar root@<NODE_IP>:/tmp/eov-flask.tar
ssh root@<NODE_IP> "sudo k3s ctr images import /tmp/eov-flask.tar && rm /tmp/eov-flask.tar"
rm eov-flask.tar

# Step 3: Verify kubectl is configured
kubectl cluster-info

# Step 4: Apply configuration to Kubernetes
kubectl apply -f eov-flask-deployment.yaml
kubectl apply -f eov-flask-ingress.yaml

# Step 5: Wait for deployments to be ready
kubectl rollout status deployment/eov-flask -n default --timeout=5m

# Step 6: Verify deployment
kubectl get services -n default
kubectl get ingress -n default
```

### Option 4: Manual Tailscale Setup (Optional)
```bash
# Step 1: Get your Tailscale auth key from https://login.tailscale.com/admin/settings/keys

# Step 2: Create the Tailscale secret
kubectl create secret generic tailscale-auth \
  --from-literal=auth-key="<YOUR_AUTH_KEY>" \
  -n default

# Step 3: Apply Tailscale configuration
kubectl apply -f tailscale-deployment.yaml

# Step 4: Wait for Tailscale pod to be ready
kubectl rollout status deployment/eov-flask-tailscale -n default --timeout=2m

# Step 5: Verify Tailscale registration
kubectl logs -l app=eov-flask-tailscale -n default
```

## Accessing Your Services

After deployment, your services will be available at:
- **http://$INGRESS_HOST** (k3s server / ingress endpoint you configured)
- Optionally, individual nodes: `$SERVER_NODE_HOST`, `$WORKER_NODE_HOST` (if applicable)

Both will route through the Ingress controller to the Flask application.

### Tailscale Access (if enabled)

If you've set up Tailscale integration, your service is also accessible via:
- **https://eov-flask.tailnet-name.ts.net** (replace `tailnet-name` with your actual Tailscale domain)

This requires:
1. Being connected to the same Tailscale network
2. Tailscale cert automatically provisioned by Tailscale
3. Access through encrypted Tailscale tunnel

To find your Tailscale hostname:
```bash
kubectl exec -it deployment/eov-flask-tailscale -n default -- tailscale status
```

Or check the logs:
```bash
kubectl logs -l app=eov-flask-tailscale -n default | grep -i "ipv4\|hostname"
```

### Available Routes

#### Main Application Routes
- **/** - Business card page with contact information
- **/r2.html** - ASCII art page

#### Endpoint Object Validator (EOV)
- **/v1/eov** - Validate object consistency across multiple backend IPs

Query parameters:
- `url` (required) - The URL to check
- `hash` (optional) - Expected hash to compare against
- `hash_alg` (optional) - Hash algorithm: `md5`, `sha1`, or `sha256` (default: `md5`)
- `timeout` (optional) - Request timeout in seconds (default: `30`)

Example usage:
```bash
# Basic check
curl "http://$INGRESS_HOST/v1/eov?url=https://example.com/file.mp3"

# With hash verification
curl "http://$INGRESS_HOST/v1/eov?url=https://example.com/file.mp3&hash=abc123&hash_alg=md5"

# With custom timeout for large files
curl "http://$INGRESS_HOST/v1/eov?url=https://example.com/largefile.mp3&timeout=120"
```

Response includes:
- `epoch_timestamp` - Unix timestamp when request started
- `total_time_seconds` - Total execution time
- `results` - Array of results for each backend IP with hash and status code

## What Gets Deployed

### Deployments
1. **eov-flask** - 2 replicas of Flask application
   - Routes: `/`, `/r2.html`, `/v1/eov`
   - Python Flask application with requests library
   - Exposes on port 5000 (via service on port 80)

### Services
- **eov-flask-service** - ClusterIP service routing to Flask pods on port 80

### Ingress
- Routes all HTTP traffic to eov-flask-service

### ConfigMaps
- **flask-rr-code** - Contains the Flask application code

## Verification

### Check Status
```bash
chmod +x status.sh
./status.sh
```

Note: `status.sh` was updated to fix a JSONPath filter that previously caused a parsing error when reporting services listening on port 80. The script now prints services that expose port 80 in the format `SERVICE_NAME<TAB>NAMESPACE`.

Example output (Port 80 section):

```
Port 80 Status:
Services listening on port 80:
eov-flask-service	default
```

Compatibility: the check uses `kubectl`'s JSONPath engine. If you see JSONPath parsing errors, try upgrading `kubectl` to a recent version.

### Manual Checks
```bash
# See all resources
kubectl get all -n default

# Check specific deployments
kubectl get deployments -n default
kubectl get services -n default
kubectl get ingress -n default

# View logs
kubectl logs -l app=flask-rr


# Test connectivity
curl http://$INGRESS_HOST
curl http://$WORKER_NODE_HOST  # optional if multi-node

# Test EOV endpoint
curl "http://$INGRESS_HOST/v1/eov?url=https://example.com/test.html"
```

## Troubleshooting

### Services not getting external IP
If `kubectl get services` shows `<pending>` for the EXTERNAL-IP, ensure:
- Your cluster has an Ingress controller installed (e.g., nginx-ingress, traefik)
- The Ingress controller is properly configured to route traffic to the Flask service

### Pods stuck in Pending
Check if nodes are ready:
```bash
kubectl get nodes
```

View pod events:
```bash
kubectl describe pod <pod-name>
```

### Port 80 already in use
If you get binding errors, check what's running:
```bash
kubectl get services -n default -o wide
```

Remove competing services:
```bash
kubectl delete service <service-name>
```

## Rollback (Undo Deployment)

To revert to a previous state:
```bash
# Delete all deployed resources
kubectl delete -f eov-flask-deployment.yaml
kubectl delete -f eov-flask-ingress.yaml

# Delete Tailscale (if deployed)
kubectl delete -f tailscale-deployment.yaml
kubectl delete secret tailscale-auth

# Or delete specific resources
kubectl delete deployment eov-flask
kubectl delete service eov-flask-service
kubectl delete ingress eov-flask-ingress
kubectl delete configmap flask-rr-code
kubectl delete deployment eov-flask-tailscale
kubectl delete service eov-flask-tailscale-service
```

## EOV Tool

The Endpoint Object Validator (EOV) is available both as a bash script (`eov.sh`) and as a Flask route (`/v1/eov`). It's designed to verify that all backend servers behind a load-balanced hostname are serving consistent content.

### Use Cases
- Verify cache consistency across CDN nodes
- Check that all backend servers have the same file version
- Detect misconfigured load balancer backends
- Validate content deployment across distributed systems

### How It Works
1. Resolves the hostname to all backend IP addresses
2. Makes a direct request to each IP (with proper Host header for virtual hosting)
3. Computes hash of the response from each backend
4. Compares hashes to detect inconsistencies

### Bash Script Usage
```bash
chmod +x eov.sh

# Basic usage
./eov.sh https://example.com/file.mp3

# With hash verification
./eov.sh https://example.com/file.mp3 --hash abc123def456

# With custom hash algorithm
./eov.sh https://example.com/file.mp3 --hash-alg sha256

# Debug mode
./eov.sh https://example.com/file.mp3 --debug
```

## Tailscale Integration

### Overview
The Tailscale integration provides:
- Secure access to your Flask service over a private Tailscale network
- Automatic TLS certificate provisioning
- DNS name resolution within your tailnet
- Encrypted tunnel to the service

### Prerequisites
- Tailscale account (free at https://tailscale.com)
- Auth key from your Tailscale admin panel

### Setup

#### Automated Setup (Recommended)
```bash
chmod +x tailscale-setup.sh
./tailscale-setup.sh
```

This interactive script will:
1. Prompt for your Tailscale auth key
2. Create the authentication secret
3. Deploy the Tailscale proxy container
4. Wait for the pod to be ready
5. Provide connection details

#### Manual Setup
```bash
# Step 1: Get auth key from https://login.tailscale.com/admin/settings/keys

# Step 2: Create the secret
kubectl create secret generic tailscale-auth \
  --from-literal=auth-key="<YOUR_AUTH_KEY>" \
  -n default

# Step 3: Deploy
kubectl apply -f tailscale-deployment.yaml

# Step 4: Verify
kubectl rollout status deployment/eov-flask-tailscale -n default --timeout=2m
```

### Accessing via Tailscale

Once the Tailscale pod is running:

1. **Find your Tailscale hostname:**
   ```bash
   kubectl logs -l app=eov-flask-tailscale -n default | grep -i hostname
   ```

2. **Access the service:**
   ```bash
   # Via Tailscale DNS (if DNS is configured)
   https://eov-flask.YOUR_TAILNET.ts.net

   # Or directly via Tailscale IP
   kubectl exec -it deployment/eov-flask-tailscale -n default -- tailscale status
   ```

3. **From any device on your tailnet:**
   - You can now access the service securely
   - Uses Tailscale's automatic certificate provisioning
   - All traffic is encrypted through Tailscale tunnel

### Tailscale Certificates

Tailscale automatically provides certificates for your service:
- **Domain:** `<hostname>.tailnet-name.ts.net`
- **Certificate:** Automatically generated and renewed
- **Validation:** Your device must be connected to the tailnet
- **Port:** 443 (HTTPS)

No additional certificate configuration needed - it's all handled automatically!

### Managing Tailscale Deployment

```bash
# Check Tailscale pod status
kubectl get pods -l app=eov-flask-tailscale

# View logs
kubectl logs -l app=eov-flask-tailscale

# Restart if needed
kubectl rollout restart deployment/eov-flask-tailscale

# Remove Tailscale
kubectl delete -f tailscale-deployment.yaml
kubectl delete secret tailscale-auth
```

## Additional Notes

- All resources are deployed to the `default` namespace
- ConfigMaps store your Flask application code
- The Flask service uses `ClusterIP` for internal routing through Ingress
- Flask application requires `flask` and `requests` Python packages
- EOV endpoint handles both HTTP and HTTPS URLs with proper SNI support
- Large file downloads may require increasing the timeout parameter

## Dependencies

The Flask application automatically installs:
- `flask` - Web framework
- `requests` - HTTP library for EOV functionality

## Updating ASCII Art

The ASCII art displayed on `/r2.html` is stored as base64-encoded data in the Flask application. To update it:

1. Edit the `r2-ascii.txt` file with your desired ASCII art
2. Re-encode it to base64:
```bash
cat ./r2-ascii.txt | base64 -w 0 && echo
```
3. Copy the output and replace the `encoded_ascii` value in `eov-flask-deployment.yaml`
4. Redeploy the application:
```bash
kubectl apply -f eov-flask-deployment.yaml
kubectl rollout restart deployment/eov-flask
```

## Decoding Base64 ASCII Art

To decode the base64-encoded ASCII art stored in the Flask application:

```bash
# Decode and display the ASCII art
echo "PastedBase64String" | base64 -d

# Or save to a file
echo "PastedBase64String" | base64 -d > decoded_ascii.txt

# View the file
cat decoded_ascii.txt
```

You can retrieve the current base64-encoded value from the `eov-flask-deployment.yaml` file by searching for the `encoded_ascii` variable in the ConfigMap, then decode it using the command above.

For more information on Kubernetes, visit: https://kubernetes.io/docs/
