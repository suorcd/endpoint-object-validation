# Kubernetes Cluster Deployment Guide

Flask implementation of the Endpoint Object Validator (EOV) with Kubernetes and optional Tailscale. The Flask app exposes `/v1/eov`, matching the bash script behavior in `../eov.sh`.

## Overview (dev server)
```bash
cd flask
flask --app app run --host=0.0.0.0 --port=5000           # dev server
flask --app app run --host=0.0.0.0 --port=5000 --debug   # hot reload
```
Visit http://localhost:5000

## Nix dev shell
```bash
cd ..               # repo root
nix develop         # default dev shell (Flask + bash tools)
# or pick a focused shell
nix develop .#flask # Flask-focused
cd flask
flask --app app run --host=0.0.0.0 --port=5000 --debug
```

## Files Included
- `eov-flask-deployment.yaml` — Flask app deployment and ConfigMap
- `eov-flask-ingress.yaml` — ingress routing to the Flask service
- `tailscale-deployment.yaml` — optional Tailscale proxy
- `deploy.sh` — automated deployment
- `k3s_image_push.sh` — image push helper for K3s nodes
- `tailscale-setup.sh` — automated Tailscale setup
- `status.sh` — cluster status helper
- `eov.sh` — bash reference implementation of EOV

## Deployment

### Option 1: Automated (recommended)
```bash
docker build -t eov-flask:latest .
chmod +x k3s_image_push.sh deploy.sh
./k3s_image_push.sh
./deploy.sh
```

### Option 2: Add Tailscale (after Option 1)
```bash
chmod +x tailscale-setup.sh
./tailscale-setup.sh   # prompts for auth key and deploys proxy
```

### Option 3: Manual deploy
```bash
docker build -t eov-flask:latest .
docker save eov-flask:latest -o eov-flask.tar
scp eov-flask.tar root@<NODE_IP>:/tmp/eov-flask.tar
ssh root@<NODE_IP> "sudo k3s ctr images import /tmp/eov-flask.tar && rm /tmp/eov-flask.tar"
rm eov-flask.tar

kubectl apply -f eov-flask-deployment.yaml
kubectl apply -f eov-flask-ingress.yaml
kubectl rollout status deployment/eov-flask -n default --timeout=5m
kubectl get services -n default
kubectl get ingress -n default
```

### Option 4: Manual Tailscale setup (optional)
```bash
kubectl create secret generic tailscale-auth \
  --from-literal=auth-key="<YOUR_AUTH_KEY>" \
  -n default
kubectl apply -f tailscale-deployment.yaml
kubectl rollout status deployment/eov-flask-tailscale -n default --timeout=2m
kubectl logs -l app=eov-flask-tailscale -n default | grep -i hostname
```

## Access
- Ingress: `http://$INGRESS_HOST`
- Tailscale (if enabled): `https://eov-flask.<tailnet>.ts.net` (replace `<tailnet>`)

## EOV: Bash vs Flask
- Bash: `../eov.sh` CLI for direct checks.
- Flask: `/v1/eov` HTTP endpoint providing the same validation via API.

### `/v1/eov` parameters
- `url` (required) — target URL
- `hash` (optional) — expected hash
- `hash_alg` (optional) — `md5` (default), `sha1`, `sha256`
- `timeout` (optional) — seconds (default 30)

Example:
```bash
curl "http://$INGRESS_HOST/v1/eov?url=https://example.com/file.mp3&hash=abc123&hash_alg=md5"
```

### Other routes
- `/` — business card page
- `/r2.html` — ASCII art page

## Verify
```bash
chmod +x status.sh
./status.sh
kubectl get all -n default
kubectl logs -l app=eov-flask
```

## Troubleshooting
- Services pending EXTERNAL-IP: ensure an ingress controller is installed/configured.
- Pods Pending: `kubectl get nodes` then `kubectl describe pod <pod>` for events.
- Port 80 conflicts: `kubectl get services -n default -o wide` and remove conflicting services.

## Rollback
```bash
kubectl delete -f eov-flask-deployment.yaml
kubectl delete -f eov-flask-ingress.yaml
kubectl delete -f tailscale-deployment.yaml
kubectl delete secret tailscale-auth
```

## ASCII art (r2.html)
ASCII is base64 in `eov-flask-deployment.yaml` ConfigMap.
```bash
# encode
cat ./r2-ascii.txt | base64 -w 0 && echo

# decode existing value
echo "PastedBase64String" | base64 -d > decoded_ascii.txt
```
Update the `encoded_ascii` value in the manifest and redeploy:
```bash
kubectl apply -f eov-flask-deployment.yaml
kubectl rollout restart deployment/eov-flask
```
