from flask import Flask, Response, request, jsonify, url_for, send_from_directory
import base64
import subprocess
import os
import hashlib
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from urllib.parse import urlparse
import urllib3
import socket
import yaml
import csv
import io

# Disable SSL warnings when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder='static', static_url_path='/static')

# Base64 encoded ASCII art
encoded_ascii = "Li0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0uCnwgTmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAgICAgICAgICAgfAp8IE5ldmVyIGdvbm5hIGxldCB5b3UgZG93biAgICAgICAgIHwKfCBOZXZlciBnb25uYSBydW4gYXJvdW5kIGFuZCBkZXNlcnR8CnwgeW91ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfAonLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLScKICAgICAgICAgICAgLj0oKCg9LiAgICAgICAKICAgICAgICAgIGk7JyAgIGA6aSAgICAgIAogICAgICAgICAgIV9fICAgX18hICAgICAgCiAgICAgICAgICh+KF8pLShfKX4pICAgICAKICAgICAgICAgIHwgICBuICAgwqEgICAgICAKICAgICAgICAgIFwgIC0gIC8gICAgICAgCiAgICAgICAgICAhYC0tLSchICAgICAgIAogICAgICAgICAgL2AtLl8uLSdcICAgICAgCiAgICBfLi1+J1xfLyB8b1xfL2B+LS5fIAogICAgJyAgICAgICAgfG8gICAgICAgIGAKICAgIFwuICAgICAgX3xfICAgICAgLi8gCiAgICAgIGAtLiAgICAgICAgICAuLScgICAKICAgIGB+LS0tLS0tficK"

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route("/r2.html")
def r2():
    # Decode the base64 ASCII art
    ascii_art = base64.b64decode(encoded_ascii).decode('utf-8')
    favicon_url = url_for('static', filename='favicon.ico', _scheme=request.scheme, _external=True)
    style_url = url_for('static', filename='style.css', _scheme=request.scheme, _external=True)
    html = f"""<!DOCTYPE html>
    <html>
        <head>
            <title>eov-flask</title>
            <link rel="shortcut icon" href="{favicon_url}">
            <link rel="stylesheet" href="{style_url}">
            <style>
                pre {{
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    text-align: center;
                    margin: 0;
                }}
            </style>
        </head>
        <body>
            <div class="panel">
                <pre>{ascii_art}</pre>
            </div>
        </body>
    </html>
    """
    return Response(html, mimetype="text/html")

@app.route("/v1/eov")
def v1_eov():
    """
    Endpoint Object Validation - Python implementation of eov.sh
    """
    url = request.args.get('url')
    expected_hash = request.args.get('hash')
    hash_alg = request.args.get('hash_alg', 'md5').lower()
    timeout = int(request.args.get('timeout', 33))
    format = request.args.get('format', 'json').lower()
    
    # Simple Security Guardrail: Prevent scanning localhost or metadata services
    # (Note: A robust production app needs a more comprehensive blocklist)
    forbidden_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']
    
    # Record start time
    start_time = time.time()
    start_epoch = int(start_time)
    
    if not url:
        return jsonify({
            'error': 'URL parameter is required',
            'usage': '/v1/eov?url=<URL>&hash=<HASH>&hash_alg=<md5|sha1|sha256>&timeout=<SECONDS>&format=<json|yaml|csv>'
        }), 400
    
    # Parse URL
    parsed = urlparse(url)
    hostname = parsed.hostname
    protocol = 443 if parsed.scheme == 'https' else 80
    
    if not hostname or hostname in forbidden_hosts:
        return jsonify({'error': 'Invalid or forbidden hostname'}), 400
    
    # Get hash function
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    
    if hash_alg not in hash_functions:
        return jsonify({'error': f'Unsupported hash algorithm: {hash_alg}'}), 400
    
    hash_func = hash_functions[hash_alg]
    
    # Resolve hostname to IP addresses using system DNS
    try:
        ips = socket.gethostbyname_ex(hostname)[2]
    except Exception as e:
        return jsonify({'error': f'Failed to resolve hostname: {str(e)}'}), 500
    
    results = []
    
    # Check each IP
    for ip in ips:
        try:
            # Create a session with custom DNS resolution
            session = requests.Session()
            
            # For HTTPS, we need to connect to IP but use hostname for SNI
            if parsed.scheme == 'https':
                session.mount('https://', HTTPAdapter())
                
                # Monkey patch for this specific request
                # NOTE: This is a hacky way to force DNS resolution for SNI requests
                original_getaddrinfo = socket.getaddrinfo
                def patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
                    if host == hostname:
                        # Return our specific IP
                        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port))]
                    return original_getaddrinfo(host, port, family, type, proto, flags)
                
                socket.getaddrinfo = patched_getaddrinfo
                try:
                    response = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
                finally:
                    socket.getaddrinfo = original_getaddrinfo
            else:
                # For HTTP, simple replacement works fine
                ip_url = url.replace(hostname, ip)
                response = session.get(
                    ip_url,
                    headers={'Host': hostname},
                    timeout=timeout,
                    allow_redirects=True
                )
            
            # Compute hash of content
            content_hash = hash_func(response.content).hexdigest()
            
            result = {
                'ip': ip,
                'status_code': response.status_code,
                'hash': content_hash,
                'hash_alg': hash_alg
            }
            
            # Compare with expected hash if provided
            if expected_hash:
                result['hash_matches'] = (content_hash == expected_hash)
            
            results.append(result)
            
        except Exception as e:
            results.append({
                'ip': ip,
                'error': str(e)
            })
    
    # Calculate total time
    end_time = time.time()
    total_time = round(end_time - start_time, 3)
    
    data = {
        'url': url,
        'hostname': hostname,
        'protocol': protocol,
        'hash_alg': hash_alg,
        'expected_hash': expected_hash,
        'epoch_timestamp': start_epoch,
        'total_time_seconds': total_time,
        'results': results
    }
    
    if format == 'json':
        return jsonify(data)
    elif format == 'yaml':
        return Response(yaml.dump(data), mimetype='text/yaml')
    elif format == 'csv':
        output = io.StringIO()
        if results:
            all_keys = set()
            for r in results:
                all_keys.update(r.keys())
            fieldnames = sorted(all_keys)
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        return Response(output.getvalue(), mimetype='text/csv')
    else:
        return jsonify({'error': f'Unsupported format: {format}'}), 400


@app.route("/")
def view_eov():
    favicon_url = url_for('static', filename='favicon.ico', _scheme=request.scheme, _external=True)
    style_url = url_for('static', filename='style.css', _scheme=request.scheme, _external=True)
    html = f"""<!DOCTYPE html>
    <html>
        <head>
            <title>View EOV</title>
            <link rel="shortcut icon" href="{favicon_url}">
            <link rel="stylesheet" href="{style_url}">
        </head>
        <body>
            <div class="panel">
                <h2>Endpoint Object Validation</h2>
                <form id="eov-form">
                    <label for="url">Target URL</label>
                    <div class="url-input-group">
                        <input id="url" name="url" type="text" placeholder="https://example.com" required>
                        <button id="submit" type="submit">Run /v1/eov</button>
                    </div>
                    
                    <details class="options-drawer">
                        <summary>Advanced Options</summary>
                        <div class="options-content">
                            <div class="option-group">
                                <label for="hash">Expected Hash (optional)</label>
                                <input id="hash" name="hash" type="text" placeholder="e.g., d41d8cd98f00b204e9800998ecf8427e">
                            </div>
                            <div class="option-group">
                                <label for="hash-alg">Hash Algorithm</label>
                                <select id="hash-alg" name="hash-alg">
                                    <option value="md5" selected>MD5</option>
                                    <option value="sha1">SHA1</option>
                                    <option value="sha256">SHA256</option>
                                </select>
                            </div>
                            <div class="option-group">
                                <label for="timeout">Timeout (seconds)</label>
                                <input id="timeout" name="timeout" type="number" value="33" min="1" max="300">
                            </div>
                            <div class="option-group">
                                <label for="format">Response Format</label>
                                <select id="format" name="format">
                                    <option value="json" selected>JSON</option>
                                    <option value="yaml">YAML</option>
                                    <option value="csv">CSV</option>
                                </select>
                            </div>
                        </div>
                    </details>
                </form>
                <textarea id="output" readonly placeholder="Results will appear here..."></textarea>
            </div>

            <script>
                const form = document.getElementById('eov-form');
                const urlInput = document.getElementById('url');
                const submitBtn = document.getElementById('submit');
                const output = document.getElementById('output');
                const hashInput = document.getElementById('hash');
                const hashAlgSelect = document.getElementById('hash-alg');
                const timeoutInput = document.getElementById('timeout');
                const formatSelect = document.getElementById('format');

                form.addEventListener('submit', async (event) => {{
                    event.preventDefault();
                    const targetUrl = urlInput.value.trim();
                    if (!targetUrl) {{
                        output.value = 'Please provide a URL.';
                        return;
                    }}

                    submitBtn.disabled = true;
                    output.value = 'Running /v1/eov...';

                    try {{
                        const params = new URLSearchParams({{
                            url: targetUrl,
                            format: formatSelect.value,
                            timeout: timeoutInput.value
                        }});
                        
                        const hashValue = hashInput.value.trim();
                        if (hashValue) {{
                            params.append('hash', hashValue);
                            params.append('hash-alg', hashAlgSelect.value);
                        }}

                        const resp = await fetch('/v1/eov?' + params.toString());
                        const text = await resp.text();
                        
                        if (formatSelect.value === 'json') {{
                            try {{
                                const data = JSON.parse(text);
                                output.value = JSON.stringify(data, null, 2);
                            }} catch (parseErr) {{
                                output.value = text;
                            }}
                        }} else {{
                            output.value = text;
                        }}
                    }} catch (err) {{
                        output.value = `Request failed: ${{err}}`;
                    }} finally {{
                        submitBtn.disabled = false;
                    }}
                }});

                const piLink = document.getElementById('pi-link');
                piLink.addEventListener('click', (e) => {{
                    if (!(e.ctrlKey && e.shiftKey)) {{
                        e.preventDefault();
                    }}
                }});
            </script>
            <div class="easter-egg">
                <a id="pi-link" href="/r2.html" title="Dale: Click it and then press Ctrl+Shift">π</a>
            </div>
        </body>
    </html>
    """
    return Response(html, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)