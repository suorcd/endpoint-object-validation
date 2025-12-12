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
                        <input id="url" name="url" type="text" placeholder="https://example.com/example.jpg" required>
                        <button id="submit" type="submit">Run /v1/eov</button>
                    </div>
                </form>
                
                <div id="summary" class="summary-output">
                    <div class="help-text">
                        <p>Check if all IP addresses for a hostname return identical content.</p>
                        <p style="margin-top: 8px; font-size: 0.9em; color: var(--muted);">Enter a URL above to validate object consistency and detect discrepancies.</p>
                    </div>
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
                
                <details id="full-results-drawer" class="options-drawer" style="display: none;">
                    <summary id="full-results-title">Full Results (JSON)</summary>
                    <div class="options-content">
                        <textarea id="output" readonly></textarea>
                    </div>
                </details>
                
                <details id="curl-drawer" class="options-drawer" style="display: none;">
                    <summary>Curl Command</summary>
                    <div class="options-content">
                        <input id="curl-command" type="text" readonly placeholder="Run a query to generate the curl command...">
                    </div>
                </details>
            </div>

            <script>
                const form = document.getElementById('eov-form');
                const urlInput = document.getElementById('url');
                const submitBtn = document.getElementById('submit');
                const summary = document.getElementById('summary');
                const fullResultsDrawer = document.getElementById('full-results-drawer');
                const fullResultsTitle = document.getElementById('full-results-title');
                const output = document.getElementById('output');
                const hashInput = document.getElementById('hash');
                const hashAlgSelect = document.getElementById('hash-alg');
                const timeoutInput = document.getElementById('timeout');
                const formatSelect = document.getElementById('format');
                const curlDrawer = document.getElementById('curl-drawer');
                const curlCommand = document.getElementById('curl-command');

                form.addEventListener('submit', async (event) => {{
                    event.preventDefault();
                    const targetUrl = urlInput.value.trim();
                    if (!targetUrl) {{
                        summary.innerHTML = '<p style="text-align: center; color: var(--accent);">Please provide a URL.</p>';
                        return;
                    }}

                    submitBtn.disabled = true;
                    summary.innerHTML = '<p style="text-align: center; color: var(--muted);">Running /v1/eov...</p>';
                    fullResultsDrawer.style.display = 'none';

                    try {{
                        const params = new URLSearchParams({{
                            url: targetUrl,
                            format: formatSelect.value,
                            timeout: timeoutInput.value,
                            hash_alg: hashAlgSelect.value
                        }});
                        
                        const hashValue = hashInput.value.trim();
                        if (hashValue) {{
                            params.append('hash', hashValue);
                        }}

                        const apiUrl = window.location.origin + '/v1/eov?' + params.toString();
                        
                        // Generate curl command
                        curlCommand.value = `curl '${{apiUrl}}'`;
                        curlDrawer.style.display = 'block';
                        
                        const resp = await fetch('/v1/eov?' + params.toString());
                        const text = await resp.text();
                        
                        if (formatSelect.value === 'json') {{
                            try {{
                                const data = JSON.parse(text);
                                
                                // Check if all hashes match
                                let hashValidation = null;
                                if (data.results && data.results.length > 0) {{
                                    const hashes = data.results
                                        .filter(r => r.hash)
                                        .map(r => r.hash);
                                    
                                    if (hashes.length > 0) {{
                                        const allMatch = hashes.every(h => h === hashes[0]);
                                        const uniqueHashes = [...new Set(hashes)];
                                        
                                        hashValidation = {{
                                            total_ips: data.results.length,
                                            unique_hashes: uniqueHashes.length,
                                            all_match: allMatch
                                        }};
                                        
                                        if (!allMatch) {{
                                            hashValidation.mismatches = uniqueHashes.map(hash => ({{
                                                hash: hash,
                                                ips: data.results
                                                    .filter(r => r.hash === hash)
                                                    .map(r => r.ip)
                                            }}));
                                        }}
                                        
                                        data.hash_validation = hashValidation;
                                    }}
                                }}
                                
                                // Generate summary HTML
                                let summaryHTML = '<div class="result-summary">';
                                summaryHTML += `<h3>${{data.hostname}}</h3>`;
                                summaryHTML += `<p class="result-detail">Checked ${{data.results.length}} IP${{data.results.length !== 1 ? 's' : ''}} in ${{data.total_time_seconds}}s</p>`;
                                
                                // Check if expected hash matches
                                const expectedHash = hashInput.value.trim();
                                let expectedHashMatches = null;
                                if (expectedHash && hashValidation) {{
                                    const hashes = data.results
                                        .filter(r => r.hash)
                                        .map(r => r.hash);
                                    expectedHashMatches = hashes.some(h => h.toLowerCase() === expectedHash.toLowerCase());
                                }}
                                
                                if (hashValidation) {{
                                    if (expectedHashMatches !== null) {{
                                        if (expectedHashMatches) {{
                                            summaryHTML += '<p class="result-status success">✓ Expected hash found</p>';
                                        }} else {{
                                            summaryHTML += '<p class="result-status error">✗ Expected hash NOT found</p>';
                                        }}
                                    }}
                                    
                                    if (hashValidation.all_match) {{
                                        summaryHTML += '<p class="result-status success">✓ All hashes match</p>';
                                    }} else {{
                                        summaryHTML += '<p class="result-status error">✗ Hash mismatch detected</p>';
                                        summaryHTML += `<p class="result-detail">${{hashValidation.unique_hashes}} unique hash${{hashValidation.unique_hashes !== 1 ? 'es' : ''}} found</p>`;
                                    }}
                                }} else {{
                                    const successCount = data.results.filter(r => r.status_code === 200 || r.status_code === 301 || r.status_code === 302).length;
                                    const errorCount = data.results.filter(r => r.error).length;
                                    if (errorCount === 0 && successCount > 0) {{
                                        summaryHTML += '<p class="result-status success">✓ All requests successful</p>';
                                    }} else if (errorCount > 0) {{
                                        summaryHTML += `<p class="result-status error">✗ ${{errorCount}} error${{errorCount !== 1 ? 's' : ''}}</p>`;
                                    }}
                                }}
                                
                                summaryHTML += '</div>';
                                summary.innerHTML = summaryHTML;
                                
                                // Populate full results
                                output.value = JSON.stringify(data, null, 2);
                                fullResultsTitle.textContent = 'Full Results (JSON)';
                                fullResultsDrawer.style.display = 'block';
                            }} catch (parseErr) {{
                                summary.innerHTML = `<p class="result-status error">Error parsing response</p>`;
                                output.value = text;
                                fullResultsTitle.textContent = 'Full Results (JSON)';
                                fullResultsDrawer.style.display = 'block';
                            }}
                        }} else {{
                            // For YAML/CSV, try to parse as JSON first to get summary info
                            // (the backend sends YAML/CSV but we can request JSON separately for summary)
                            try {{
                                // Make a separate JSON request for summary data
                                const jsonParams = new URLSearchParams(params);
                                jsonParams.set('format', 'json');
                                const jsonResp = await fetch('/v1/eov?' + jsonParams.toString());
                                const jsonData = await jsonResp.json();
                                
                                // Check if all hashes match
                                let hashValidation = null;
                                if (jsonData.results && jsonData.results.length > 0) {{
                                    const hashes = jsonData.results
                                        .filter(r => r.hash)
                                        .map(r => r.hash);
                                    
                                    if (hashes.length > 0) {{
                                        const allMatch = hashes.every(h => h === hashes[0]);
                                        const uniqueHashes = [...new Set(hashes)];
                                        hashValidation = {{
                                            total_ips: jsonData.results.length,
                                            unique_hashes: uniqueHashes.length,
                                            all_match: allMatch
                                        }};
                                    }}
                                }}
                                
                                // Generate summary HTML
                                let summaryHTML = '<div class="result-summary">';
                                summaryHTML += `<h3>${{jsonData.hostname}}</h3>`;
                                summaryHTML += `<p class="result-detail">Checked ${{jsonData.results.length}} IP${{jsonData.results.length !== 1 ? 's' : ''}} in ${{jsonData.total_time_seconds}}s</p>`;
                                
                                // Check if expected hash matches
                                const expectedHash = hashInput.value.trim();
                                let expectedHashMatches = null;
                                if (expectedHash && hashValidation) {{
                                    const hashes = jsonData.results
                                        .filter(r => r.hash)
                                        .map(r => r.hash);
                                    expectedHashMatches = hashes.some(h => h.toLowerCase() === expectedHash.toLowerCase());
                                }}
                                
                                if (hashValidation) {{
                                    if (expectedHashMatches !== null) {{
                                        if (expectedHashMatches) {{
                                            summaryHTML += '<p class="result-status success">✓ Expected hash found</p>';
                                        }} else {{
                                            summaryHTML += '<p class="result-status error">✗ Expected hash NOT found</p>';
                                        }}
                                    }}
                                    
                                    if (hashValidation.all_match) {{
                                        summaryHTML += '<p class="result-status success">✓ All hashes match</p>';
                                    }} else {{
                                        summaryHTML += '<p class="result-status error">✗ Hash mismatch detected</p>';
                                        summaryHTML += `<p class="result-detail">${{hashValidation.unique_hashes}} unique hash${{hashValidation.unique_hashes !== 1 ? 'es' : ''}} found</p>`;
                                    }}
                                }} else {{
                                    const successCount = jsonData.results.filter(r => r.status_code === 200 || r.status_code === 301 || r.status_code === 302).length;
                                    const errorCount = jsonData.results.filter(r => r.error).length;
                                    if (errorCount === 0 && successCount > 0) {{
                                        summaryHTML += '<p class="result-status success">✓ All requests successful</p>';
                                    }} else if (errorCount > 0) {{
                                        summaryHTML += `<p class="result-status error">✗ ${{errorCount}} error${{errorCount !== 1 ? 's' : ''}}</p>`;
                                    }}
                                }}
                                
                                summaryHTML += '</div>';
                                summary.innerHTML = summaryHTML;
                            }} catch (err) {{
                                summary.innerHTML = `<p class="result-detail" style="text-align: center;">Response received (${{formatSelect.value.toUpperCase()}})</p>`;
                            }}
                            
                            output.value = text;
                            fullResultsTitle.textContent = `Full Results (${{formatSelect.value.toUpperCase()}})`;
                            fullResultsDrawer.style.display = 'block';
                        }}
                    }} catch (err) {{
                        summary.innerHTML = `<p class="result-status error">Request failed: ${{err}}</p>`;
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