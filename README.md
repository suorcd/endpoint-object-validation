# Endpoint Object Validation

This repository provides endpoint object validation in two implementations:

1. **Bash Script (`eov.sh`)** - Lightweight CLI tool
2. **Flask Web Service** - HTTP API with Kubernetes deployment

## Bash Script Usage

```shell
./eov.sh <URL> [--hash HASH] [--file FILE] [--hash-alg HASH_ALG] [--debug]


## nix Usage

To use the `eov.sh` script, follow the instructions below:

### Building the Package

1. **Build the package using Nix Flakes**:
   ```shell
   nix build
   ```

Examples
Basic Usage:
`./result/bin/eov.sh http://example.com`
With Hash Comparison:
`./result/bin/eov.sh http://example.com --hash d41d8cd98f00b204e9800998ecf8427e`
With File Hash Comparison:
`./result/bin/eov.sh http://example.com --file /path/to/file`
With Custom Hash Algorithm:
`./result/bin/eov.sh http://example.com --hash-alg sha512`
With Debug Mode:
`./result/bin/eov.sh http://example.com --debug`



### nix Explanation

1. **Building the Package**: Instructions to build the package using Nix Flakes.
2. **Running the Script**: Instructions to run the script from the built package.
3. **Arguments**: Detailed explanation of the command-line arguments.
4. **Examples**: Usage examples demonstrating different ways to use the script.
````

## Flask Web Service
See [flask/README.md](flask/README.md) for the Flask implementation with:
- HTTP API endpoint for object validation
- Kubernetes deployment configurations
- Tailscale integration
- Development and production setup

## Development with Nix
[...]