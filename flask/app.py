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
import concurrent.futures
from werkzeug.middleware.proxy_fix import ProxyFix

# Disable SSL warnings when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder='static', static_url_path='/static')

# Fix: Tell Flask to trust X-Forwarded-* headers from the proxy (Tailscale/Ingress)
# x_proto=1 ensures request.scheme matches the protocol used by the client (http vs https)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Base64 encoded ASCII art
encoded_ascii = "Li0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0uCnwgTmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAgICAgICAgICAgfAp8IE5ldmVyIGdvbm5hIGxldCB5b3UgZG93biAgICAgICAgIHwKfCBOZXZlciBnb25uYSBydW4gYXJvdW5kIGFuZCBkZXNlcnR8CnwgeW91ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfAonLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLScKICAgICAgICAgICAgLj0oKCg9LiAgICAgICAKICAgICAgICAgIGk7JyAgIGA6aSAgICAgIAogICAgICAgICAgIV9fICAgX18hICAgICAgCiAgICAgICAgICh+KF8pLShfKX4pICAgICAKICAgICAgICAgIHwgICBuICAgwqEgICAgICAKICAgICAgICAgIFwgIC0gIC8gICAgICAgCiAgICAgICAgICAhYC0tLSchICAgICAgIAogICAgICAgICAgL2AtLl8uLSdcICAgICAgCiAgICBfLi1+J1xfLyB8b1xfL2B+LS5fIAogICAgJyAgICAgICAgfG8gICAgICAgIGAKICAgIFwuICAgICAgX3xfICAgICAgLi8gCiAgICAgIGAtLiAgICAgICAgICAuLScgICAKICAgIGB+LS0tLS0tficK"

class SniAdapter(HTTPAdapter):
    """
    Adapter to force a specific server_hostname (SNI) 
    while connecting to a direct IP address in the URL.
    """
    def __init__(self, sni_hostname, **kwargs):
        self.sni_hostname = sni_hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        # Inject the SNI hostname into the SSL context of the pool
        pool_kwargs['server_hostname'] = self.sni_hostname
        # Note: assert_hostname is usually for verifying the cert matches the hostname.
        # Since we use verify=False often in this tool, this ensures the handshake uses the right name.
        pool_kwargs['assert_hostname'] = self.sni_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

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

def check_single_ip(ip, url, hostname, scheme, timeout, hash_func, hash_alg, expected_hash):
    """
    Helper function to check a single IP. 
    Designed to be run in a thread.
    """
    result = {
        'ip': ip,
        'status_code': None,
        'hash': None,
        'hash_alg': hash_alg,
        'file_size_bytes': None
    }
    
    try:
        session = requests.Session()
        
        if scheme == 'https':
            # Use the SniAdapter to connect to the IP but send the correct Hostname in SNI
            # Mount it to the specific IP URL structure
            prefix = f"https://{ip}"
            adapter = SniAdapter(sni_hostname=hostname)
            session.mount(prefix, adapter)
            
            # Construct URL using IP but keeping path/query
            # We replace hostname with IP in the URL
            target_url = url.replace(hostname, ip, 1)
            
            # Host header is still good practice even with SNI
            response = session.get(
                target_url, 
                headers={'Host': hostname}, 
                timeout=timeout, 
                allow_redirects=True, 
                verify=False
            )
        else:
            # For HTTP, simple replacement works fine
            target_url = url.replace(hostname, ip, 1)
            response = session.get(
                target_url,
                headers={'Host': hostname},
                timeout=timeout,
                allow_redirects=True
            )
        
        # Get content and compute hash
        content = response.content
        content_hash = hash_func(content).hexdigest()
        file_size = len(content)
        
        result['status_code'] = response.status_code
        result['hash'] = content_hash
        result['file_size_bytes'] = file_size
        
        # Compare with expected hash if provided
        if expected_hash:
            result['hash_matches'] = (content_hash == expected_hash)
            
    except Exception as e:
        result['error'] = str(e)
        
    return result

def query_external_eov(eov_base_url, target_url, params):
    """
    Query an external EOV instance and return its results.
    """
    # Normalize EOV URL
    eov_url = eov_base_url.strip()
    if not eov_url.startswith('http'):
        eov_url = f'https://{eov_url}'
    
    # Ensure it points to the API endpoint
    if not eov_url.endswith('/v1/eov'):
        eov_url = eov_url.rstrip('/') + '/v1/eov'
        
    query_params = {
        'url': target_url,
        'format': 'json',
        'hash_alg': params.get('hash_alg', 'md5'),
        'timeout': params.get('timeout', 33)
    }
    
    if params.get('hash'):
        query_params['hash'] = params['hash']

    try:
        resp = requests.get(eov_url, params=query_params, timeout=int(params.get('timeout', 33)) + 5, verify=False)
        resp.raise_for_status()
        data = resp.json()
        
        results = data.get('results', [])
        # Tag results with the source
        for r in results:
            r['eov_server'] = eov_base_url
            
        return results
    except Exception as e:
        return [{
            'eov_server': eov_base_url,
            'error': f"EOV Node Error: {str(e)}",
            'ip': '0.0.0.0', # Placeholder to ensure it shows up
            'status_code': 0
        }]

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
    eov_endpoints_str = request.args.get('eov_endpoints', '').strip()
    
    # Simple Security Guardrail for TARGET URL
    # We want to prevent the tool from scanning the container's own network or localhost services
    forbidden_target_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']
    
    # Record start time
    start_time = time.time()
    start_epoch = int(start_time)
    
    if not url:
        return jsonify({
            'error': 'URL parameter is required',
            'usage': '/v1/eov?url=<URL>&hash=<HASH>&hash_alg=<md5|sha1|sha256>&timeout=<SECONDS>&format=<json|yaml|csv>&eov_endpoints=<URL1,URL2>'
        }), 400
    
    # Parse URL
    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme
    protocol = 443 if scheme == 'https' else 80
    
    if not hostname or hostname in forbidden_target_hosts:
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
    results = []
    
    # Logic Branch: Remote EOV Aggregation vs Local Check
    if eov_endpoints_str:
        # --- REMOTE EOV MODE ---
        endpoints = [x.strip() for x in eov_endpoints_str.split(',') if x.strip()]
        
        # Guardrail for external EOV URLs too
        valid_endpoints = []
        for ep in endpoints:
            ep_parsed = urlparse(ep if ep.startswith('http') else f'http://{ep}')
            # We allow localhost/127.0.0.1 for EOV aggregation (self-referencing), 
            # but we still block cloud metadata service.
            if ep_parsed.hostname and ep_parsed.hostname != '169.254.169.254':
                valid_endpoints.append(ep)
        
        if not valid_endpoints:
             return jsonify({'error': 'No valid external EOV endpoints provided'}), 400

        params = {
            'hash': expected_hash,
            'hash_alg': hash_alg,
            'timeout': timeout
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(valid_endpoints)) as executor:
            future_to_url = {
                executor.submit(query_external_eov, ep, url, params): ep 
                for ep in valid_endpoints
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                external_results = future.result()
                results.extend(external_results)
                
    else:
        # --- LOCAL MODE ---
        # Resolve hostname to IP addresses using system DNS
        try:
            ips = socket.gethostbyname_ex(hostname)[2]
        except Exception as e:
            return jsonify({'error': f'Failed to resolve hostname: {str(e)}'}), 500
        
        # Use ThreadPoolExecutor for parallel execution
        max_workers = min(len(ips), 20)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(
                    check_single_ip, 
                    ip, url, hostname, scheme, timeout, hash_func, hash_alg, expected_hash
                ): ip for ip in ips
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                res = future.result()
                res['eov_server'] = 'local'
                results.append(res)
    
    # Sort results
    # If using multiple EOVs, we might have duplicate IPs. Sorting by IP groups them.
    results.sort(key=lambda x: (x.get('ip', ''), x.get('eov_server', '')))

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
            <style>
                /* Add a simple spinner */
                .spinner {{
                    display: inline-block;
                    width: 20px;
                    height: 20px;
                    border: 3px solid rgba(255,255,255,.3);
                    border-radius: 50%;
                    border-top-color: #fff;
                    animation: spin 1s ease-in-out infinite;
                    margin-right: 8px;
                    vertical-align: middle;
                }}
                @keyframes spin {{
                    to {{ transform: rotate(360deg); }}
                }}
                .hidden {{
                    display: none;
                }}
            </style>
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
                            <label for="eov-endpoints">External EOV Endpoints (Optional)</label>
                            <input id="eov-endpoints" name="eov-endpoints" type="text" placeholder="https://eov-us.example.com, https://eov-eu.example.com">
                            <p style="margin: 4px 0 0 0; font-size: 0.8em; color: var(--muted);">Comma-separated. Defaults to current instance; add others to aggregate results.</p>
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
                    <summary>Full Results (JSON)</summary>
                    <div class="options-content">
                        <textarea id="output" readonly></textarea>
                    </div>
                </details>
                
                <details class="options-drawer">
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
                const fullResultsSummary = fullResultsDrawer.querySelector('summary'); 
                const output = document.getElementById('output');
                const hashInput = document.getElementById('hash');
                const hashAlgSelect = document.getElementById('hash-alg');
                const timeoutInput = document.getElementById('timeout');
                const formatSelect = document.getElementById('format');
                const curlCommand = document.getElementById('curl-command');
                const eovEndpointsInput = document.getElementById('eov-endpoints');

                // Default EOV Endpoints to current origin
                if (!eovEndpointsInput.value) {{
                    eovEndpointsInput.value = window.location.origin;
                }}

                function parseCSV(text) {{
                    const lines = text.trim().split(/\\r?\\n/);
                    if (lines.length < 2) return [];
                    const headers = lines[0].split(',');
                    const hashIdx = headers.indexOf('hash');
                    const ipIdx = headers.indexOf('ip');
                    const errIdx = headers.indexOf('error');
                    const statusIdx = headers.indexOf('status_code');
                    
                    return lines.slice(1).map(line => {{
                        const vals = line.split(',');
                        const obj = {{}};
                        if (hashIdx > -1) obj.hash = vals[hashIdx];
                        if (ipIdx > -1) obj.ip = vals[ipIdx];
                        if (errIdx > -1) obj.error = vals[errIdx];
                        if (statusIdx > -1) obj.status_code = parseInt(vals[statusIdx]);
                        return obj;
                    }});
                }}

                function parseYAML(text) {{
                    const parts = text.split('results:');
                    if (parts.length < 2) return [];
                    const resultsBlock = parts[1];
                    
                    const items = [];
                    let currentItem = {{}};
                    
                    const lines = resultsBlock.split('\\n');
                    for (let line of lines) {{
                        line = line.trim();
                        if (!line) continue;
                        
                        if (line.startsWith('- ')) {{
                            if (Object.keys(currentItem).length > 0) {{
                                items.push(currentItem);
                            }}
                            currentItem = {{}};
                            line = line.substring(2);
                        }}
                        
                        const colonIdx = line.indexOf(':');
                        if (colonIdx > -1) {{
                            const k = line.substring(0, colonIdx).trim();
                            const v = line.substring(colonIdx + 1).trim();
                            currentItem[k] = v;
                        }}
                    }}
                    if (Object.keys(currentItem).length > 0) items.push(currentItem);
                    return items;
                }}

                function performAnalysis(results, hostname, totalTime, expectedHash) {{
                    let hashValidation = null;
                    if (results && results.length > 0) {{
                        const hashes = results
                            .filter(r => r.hash)
                            .map(r => r.hash);
                        
                        if (hashes.length > 0) {{
                            const allMatch = hashes.every(h => h === hashes[0]);
                            const uniqueHashes = [...new Set(hashes)];
                            
                            hashValidation = {{
                                total_ips: results.length,
                                unique_hashes: uniqueHashes.length,
                                all_match: allMatch
                            }};
                            
                            if (!allMatch) {{
                                hashValidation.mismatches = uniqueHashes.map(hash => ({{
                                    hash: hash,
                                    ips: results
                                        .filter(r => r.hash === hash)
                                        .map(r => r.ip)
                                }}));
                            }}
                        }}
                    }}
                    
                    let summaryHTML = '<div class="result-summary">';
                    if (hostname) summaryHTML += `<h3>${{hostname}}</h3>`;
                    
                    if (results.length > 0) {{
                         const timeStr = totalTime ? ` in ${{totalTime}}s` : '';
                         summaryHTML += `<p class="result-detail">Checked ${{results.length}} IP${{results.length !== 1 ? 's' : ''}}${{timeStr}}</p>`;
                         
                         if (hashValidation) {{
                            if (expectedHash) {{
                                const normExpected = expectedHash.toLowerCase().trim();
                                const normHashes = results.filter(r => r.hash).map(r => r.hash.toLowerCase());
                                const allMatchExpected = normHashes.every(h => h === normExpected);
                                
                                if (allMatchExpected) {{
                                    summaryHTML += '<p class="result-status success">✓ All hashes match expected value</p>';
                                }} else {{
                                    const allConsistent = normHashes.every(h => h === normHashes[0]);
                                    if (allConsistent) {{
                                         summaryHTML += '<p class="result-status error">✗ Hash does not match expected value</p>';
                                         summaryHTML += `<p class="result-detail">Expected: ${{expectedHash.substring(0, 16)}}...<br>Actual: ${{results[0].hash.substring(0, 16)}}...</p>`;
                                    }} else {{
                                         summaryHTML += '<p class="result-status error">✗ Hash mismatch detected</p>';
                                         const matchCount = normHashes.filter(h => h === normExpected).length;
                                         if (matchCount > 0) {{
                                            summaryHTML += `<p class="result-detail">${{matchCount}} IP(s) match expectation<br>${{results.length - matchCount}} IP(s) mismatch</p>`;
                                         }} else {{
                                            summaryHTML += `<p class="result-detail">No IPs match expected hash</p>`;
                                         }}
                                    }}
                                }}
                            }} else {{
                                if (hashValidation.all_match) {{
                                    summaryHTML += '<p class="result-status success">✓ All hashes match</p>';
                                }} else {{
                                    summaryHTML += '<p class="result-status error">✗ Hash mismatch detected</p>';
                                    summaryHTML += `<p class="result-detail">${{hashValidation.unique_hashes}} unique hash${{hashValidation.unique_hashes !== 1 ? 'es' : ''}} found</p>`;
                                }}
                            }}
                        }} else {{
                            const successCount = results.filter(r => r.status_code == 200 || r.status_code == 301 || r.status_code == 302).length;
                            const errorCount = results.filter(r => r.error).length;
                            
                            if (errorCount === 0 && successCount > 0) {{
                                summaryHTML += '<p class="result-status success">✓ All requests successful</p>';
                            }} else if (errorCount > 0) {{
                                summaryHTML += `<p class="result-status error">✗ ${{errorCount}} error${{errorCount !== 1 ? 's' : ''}}</p>`;
                            }} else {{
                                summaryHTML += '<p class="result-detail">No content hashes found</p>';
                            }}
                        }}
                    }} else {{
                        summaryHTML += '<p class="result-status success">✓ Request successful</p>';
                        summaryHTML += '<p class="result-detail">(Content analysis available via JSON/YAML parsing)</p>';
                    }}
                    
                    summaryHTML += '</div>';
                    return summaryHTML;
                }}

                form.addEventListener('submit', async (event) => {{
                    event.preventDefault();
                    const targetUrl = urlInput.value.trim();
                    if (!targetUrl) {{
                        summary.innerHTML = '<p style="text-align: center; color: var(--accent);">Please provide a URL.</p>';
                        return;
                    }}

                    submitBtn.disabled = true;
                    // Add spinner logic
                    const originalBtnText = submitBtn.innerHTML;
                    submitBtn.innerHTML = '<span class="spinner"></span>Running...';
                    summary.innerHTML = '<p style="text-align: center; color: var(--muted);">Resolving IPs and fetching content...</p>';
                    fullResultsDrawer.style.display = 'none';

                    try {{
                        const paramsObj = {{
                            url: targetUrl,
                            format: formatSelect.value,
                            timeout: timeoutInput.value,
                            hash_alg: hashAlgSelect.value
                        }};
                        
                        const endpoints = eovEndpointsInput.value.trim();
                        if (endpoints) {{
                            paramsObj.eov_endpoints = endpoints;
                        }}

                        const params = new URLSearchParams(paramsObj);
                        
                        const hashValue = hashInput.value.trim();
                        if (hashValue) {{
                            params.append('hash', hashValue);
                        }}

                        const apiUrl = window.location.origin + '/v1/eov?' + params.toString();
                        curlCommand.value = `curl '${{apiUrl}}'`;
                        
                        const resp = await fetch('/v1/eov?' + params.toString());
                        const text = await resp.text();
                        
                        fullResultsSummary.textContent = `Full Results (${{formatSelect.value.toUpperCase()}})`;
                        output.value = text;
                        fullResultsDrawer.style.display = 'block';

                        if (!resp.ok) {{
                             summary.innerHTML = `<p class="result-status error">Request failed (${{resp.status}})</p>`;
                             return;
                        }}

                        let results = [];
                        let hostname = new URL(targetUrl).hostname;
                        let totalTime = null;

                        try {{
                            if (formatSelect.value === 'json') {{
                                const data = JSON.parse(text);
                                results = data.results || [];
                                hostname = data.hostname;
                                totalTime = data.total_time_seconds;
                                output.value = JSON.stringify(data, null, 2);
                            }} else if (formatSelect.value === 'csv') {{
                                results = parseCSV(text);
                            }} else if (formatSelect.value === 'yaml') {{
                                results = parseYAML(text);
                            }}
                            
                            summary.innerHTML = performAnalysis(results, hostname, totalTime, hashValue);

                        }} catch (parseErr) {{
                            console.error(parseErr);
                            summary.innerHTML = `
                                <div class="result-summary">
                                    <h3>${{hostname}}</h3>
                                    <p class="result-status success">✓ Request successful</p>
                                    <p class="result-detail" style="font-size: 0.8em">Analysis failed (Parse Error)</p>
                                </div>`;
                        }}

                    }} catch (err) {{
                        summary.innerHTML = `<p class="result-status error">Request failed: ${{err}}</p>`;
                    }} finally {{
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = originalBtnText;
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