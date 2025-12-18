# EOV Flask Deployment - Tailscale Operator Support

## Overview
The `deploy.sh` script now supports three deployment modes for Tailscale connectivity:

1. **No Tailscale** (default) - Standard deployment with ingress
2. **`--tailscale`** - Deploys a separate Tailscale proxy container
3. **`--ts-operator`** - Uses Tailscale Operator annotations (NEW)

## Tailscale Operator Mode

The `--ts-operator` flag enables Tailscale connectivity using the Tailscale Operator, similar to the ws4kp deployment pattern.

### Prerequisites
- Tailscale Operator must be installed in your k3s cluster
- Follow the setup instructions in `/k.ser.ink/operator/README.md`

### Usage

```bash
# Deploy with Tailscale Operator
./deploy.sh --ts-operator

# View help
./deploy.sh --help
```

### How It Works
When using `--ts-operator`:
- Uses the `eov-flask-ts-operator.yaml` manifest
- Service includes Tailscale operator annotations:
  - `tailscale.com/expose: "true"`
  - `tailscale.com/hostname: "eov-flask"`
- No separate Tailscale proxy deployment needed
- No ingress is applied (Tailscale handles routing)
- Service will be accessible at `https://eov-flask.<your-tailnet>.ts.net`

### Differences from --tailscale

| Feature | `--tailscale` | `--ts-operator` |
|---------|---------------|-----------------|
| Operator Required | No | Yes |
| Extra Deployment | Yes (tailscale proxy) | No |
| Ingress Applied | Yes | No |
| Service Annotations | No | Yes |
| Pattern | Custom proxy | Operator-managed |

### Files
- `eov-flask-ts-operator.yaml` - Manifest with Tailscale operator annotations
- `eov-flask-deployment.yaml` - Standard deployment (used without flags or with `--tailscale`)
- `tailscale-deployment.yaml` - Separate Tailscale proxy (only used with `--tailscale`)

## Removing .direnv from Git

If you accidentally committed `.direnv/` to the repository:

```bash
cd /home/brentano/git-repo/github.com/suorcd/endpoint-object-validation
git rm -r --cached .direnv
git commit -m "Remove .direnv from tracking (now in .gitignore)"
```

This removes it from git tracking while keeping it locally. The `.gitignore` file already includes `.direnv/`.
