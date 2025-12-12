# Endpoint Object Validation

This repository provides endpoint object validation in two implementations:

1. **Bash Script (`eov.sh`)** — Lightweight CLI tool
2. **Flask Web Service** — HTTP API with Kubernetes deployment (implements `/v1/eov`)

## Bash Script Usage (`eov.sh`)

```bash
./eov.sh <URL> [--hash HASH] [--file FILE] [--hash-alg HASH_ALG] [--debug]

# Examples
./eov.sh http://example.com
./eov.sh http://example.com --hash d41d8cd98f00b204e9800998ecf8427e
./eov.sh http://example.com --file /path/to/file
./eov.sh http://example.com --hash-alg sha512
./eov.sh http://example.com --debug
```

**Arguments**
- `--hash HASH` — compare downloaded content hash against expected
- `--file FILE` — compute hash from local file instead of remote content
- `--hash-alg HASH_ALG` — hashing command prefix (default `md5`; expects `<alg>sum` to exist)
- `--debug` — verbose output and directory traversal

**Requirements**
- `curl`, `drill`, and the chosen hash utility (e.g., `md5sum`, `sha256sum`)
- DNS and HTTP(S) egress to the target hostname
- Bash shell

## Nix Usage

Build and run via flakes:

```bash
nix build
./result/bin/eov.sh <URL> [flags]
```

For development:

```bash
nix develop   # enter shell with dependencies
./eov.sh <URL> --debug
```

Dev shells (choose one):

```bash
# Default (Flask + bash tools)
nix develop

# Bash-only shell
nix develop .#bash

# Flask-focused shell
nix develop .#flask

# Run Flask dev server from any shell
cd flask
flask --app app run --host=0.0.0.0 --port=5000 --debug
```

## Developing `eov.sh`
- Run locally with `--debug` to inspect workdir and resolved IPs.
- Validate hashes by providing `--hash` or `--file` (the script uses `<hash_alg>sum`).
- If using ShellCheck, address warnings before committing (no config required here).

## Flask Web Service

For an HTTP API version of EOV, see `flask/README.md`. The Flask app exposes `/v1/eov` with parity to the bash script and includes Kubernetes and Tailscale deployment guides.
