from flask import Flask, Response, request, jsonify, url_for, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse
import concurrent.futures
import base64
import hashlib
import time
import requests
import urllib3
import socket
import yaml
import csv
import io

# Disable SSL warnings (necessary for direct IP connections with mismatched hostnames)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder='static', static_url_path='/static')

# Trust X-Forwarded-* headers from proxies (Tailscale/K8s Ingress)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Configuration & Constants ---

# Base64 encoded ASCII art (Easter Egg)
ASCII_ART_B64 = "Li0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0uCnwgTmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAgICAgICAgICAgfAp8IE5ldmVyIGdvbm5hIGxldCB5b3UgZG93biAgICAgICAgIHwKfCBOZXZlciBnb25uYSBydW4gYXJvdW5kIGFuZCBkZXNlcnR8CnwgeW91ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfAonLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLScKICAgICAgICAgICAgLj0oKCg9LiAgICAgICAKICAgICAgICAgIGk7JyAgIGA6aSAgICAgIAogICAgICAgICAgIV9fICAgX18hICAgICAgCiAgICAgICAgICh+KF8pLShfKX4pICAgICAKICAgICAgICAgIHwgICBuICAgwqEgICAgICAKICAgICAgICAgIFwgIC0gIC8gICAgICAgCiAgICAgICAgICAhYC0tLSchICAgICAgIAogICAgICAgICAgL2AtLl8uLSdcICAgICAgCiAgICBfLi1+J1xfLyB8b1xfL2B+LS5fIAogICAgJyAgICAgICAgfG8gICAgICAgIGAKICAgIFwuICAgICAgX3xfICAgICAgLi8gCiAgICAgIGAtLiAgICAgICAgICAuLScgICAKICAgIGB+LS0tLS0tficK"

FORBIDDEN_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'}
HASH_FUNCS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256
}

# --- Helpers ---

class SniAdapter(HTTPAdapter):
    """Adapter to force a specific server_hostname (SNI) for direct IP connections."""
    def __init__(self, sni_hostname, **kwargs):
        self.sni_hostname = sni_hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs['server_hostname'] = self.sni_hostname
        pool_kwargs['assert_hostname'] = self.sni_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

def render_page(title, content, extra_head=""):
    """Shared HTML template renderer to reduce code duplication."""
    favicon = url_for('static', filename='favicon.ico', _scheme=request.scheme, _external=True)
    style = url_for('static', filename='style.css', _scheme=request.scheme, _external=True)
    return f"""<!DOCTYPE html>
    <html>
        <head>
            <title>{title}</title>
            <link rel="shortcut icon" href="{favicon}">
            <link rel="stylesheet" href="{style}">
            {extra_head}
        </head>
        <body>
            <div class="panel">
                {content}
            </div>
        </body>
    </html>"""

def check_single_ip(ip, url, hostname, scheme, timeout, hash_alg, expected_hash):
    """Check a single IP address."""
    result = {
        'ip': ip,
        'status_code': None,
        'hash': None,
        'hash_alg': hash_alg,
        'file_size_bytes': None
    }
    
    try:
        session = requests.Session()
        target_url = url.replace(hostname, ip, 1)
        
        if scheme == 'https':
            # Mount SNI adapter for HTTPS to ensure correct handshake with IP URL
            session.mount(f"https://{ip}", SniAdapter(sni_hostname=hostname))
            response = session.get(
                target_url, headers={'Host': hostname}, timeout=timeout, 
                allow_redirects=True, verify=False
            )
        else:
            response = session.get(
                target_url, headers={'Host': hostname}, timeout=timeout, 
                allow_redirects=True
            )
        
        content = response.content
        content_hash = HASH_FUNCS[hash_alg](content).hexdigest()
        
        result.update({
            'status_code': response.status_code,
            'hash': content_hash,
            'file_size_bytes': len(content)
        })
        
        if expected_hash:
            result['hash_matches'] = (content_hash == expected_hash)
            
    except Exception as e:
        result['error'] = str(e)
        
    return result

def query_external_eov(node_url, target_url, params):
    """Query another EOV instance."""
    node_url = node_url.strip()
    if not node_url.startswith('http'):
        node_url = f'https://{node_url}'
    
    api_url = node_url.rstrip('/') + '/v1/eov'
    
    try:
        query = {
            'url': target_url, 'format': 'json',
            'hash_alg': params.get('hash_alg', 'md5'),
            'timeout': params.get('timeout', 33)
        }
        if params.get('hash'): query['hash'] = params['hash']

        resp = requests.get(api_url, params=query, timeout=int(params.get('timeout', 33)) + 5, verify=False)
        resp.raise_for_status()
        
        results = resp.json().get('results', [])
        for r in results:
            r['eov_server'] = node_url
        return results
    except Exception as e:
        return [{'eov_server': node_url, 'error': f"Node Error: {str(e)}", 'ip': '0.0.0.0', 'status_code': 0}]

# --- Routes ---

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route("/r2.html")
def r2():
    ascii_art = base64.b64decode(ASCII_ART_B64).decode('utf-8')
    style = """<style>pre { white-space: pre-wrap; word-wrap: break-word; text-align: center; margin: 0; }</style>"""
    content = f"<pre>{ascii_art}</pre>"
    return Response(render_page("eov-flask", content, style), mimetype="text/html")

@app.route("/")
def view_eov():
    # Use HTML template from a separate file or large string constant to keep this clean
    # For this streamlined file, we include the simplified HTML structure here.
    head_css = """<style>
        .spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid rgba(255,255,255,.3); border-radius: 50%; border-top-color: #fff; animation: spin 1s ease-in-out infinite; margin-right: 8px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .hidden { display: none; }
    </style>"""
    
    ui_html = """
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
                <div class="option-group"><label for="hash">Expected Hash (optional)</label><input id="hash" name="hash" type="text" placeholder="e.g., d41d8cd98f00b204e9800998ecf8427e"></div>
                <div class="option-group"><label for="hash-alg">Hash Algorithm</label><select id="hash-alg" name="hash-alg"><option value="md5" selected>MD5</option><option value="sha1">SHA1</option><option value="sha256">SHA256</option></select></div>
                <div class="option-group"><label for="eov-endpoints">External EOV Endpoints (Optional)</label><input id="eov-endpoints" name="eov-endpoints" type="text" placeholder="https://eov-us.example.com, https://eov-eu.example.com"><p style="margin: 4px 0 0 0; font-size: 0.8em; color: var(--muted);">Comma-separated. Leave empty to check locally on this node.</p></div>
                <div class="option-group"><label for="timeout">Timeout (seconds)</label><input id="timeout" name="timeout" type="number" value="33" min="1" max="300"></div>
                <div class="option-group"><label for="format">Response Format</label><select id="format" name="format"><option value="json" selected>JSON</option><option value="yaml">YAML</option><option value="csv">CSV</option></select></div>
            </div>
        </details>
        
        <details id="full-results-drawer" class="options-drawer" style="display: none;">
            <summary>Full Results (JSON)</summary>
            <div class="options-content"><textarea id="output" readonly></textarea></div>
        </details>
        
        <details id="curl-command-drawer" class="options-drawer" style="display: none;">
            <summary>Curl Command</summary>
            <div class="options-content"><input id="curl-command" type="text" readonly placeholder="Run a query to generate the curl command..."></div>
        </details>
        
        <div class="easter-egg"><a id="pi-link" href="/r2.html" title="Dale: Click it and then press Ctrl+Shift">π</a></div>

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
            const curlCommandDrawer = document.getElementById('curl-command-drawer');
            const eovEndpointsInput = document.getElementById('eov-endpoints');

            function parseCSV(text) {
                const lines = text.trim().split(/\\r?\\n/);
                if (lines.length < 2) return [];
                const headers = lines[0].split(',');
                const hashIdx = headers.indexOf('hash');
                const ipIdx = headers.indexOf('ip');
                const errIdx = headers.indexOf('error');
                const statusIdx = headers.indexOf('status_code');
                return lines.slice(1).map(line => {
                    const vals = line.split(',');
                    const obj = {};
                    if (hashIdx > -1) obj.hash = vals[hashIdx];
                    if (ipIdx > -1) obj.ip = vals[ipIdx];
                    if (errIdx > -1) obj.error = vals[errIdx];
                    if (statusIdx > -1) obj.status_code = parseInt(vals[statusIdx]);
                    return obj;
                });
            }

            function parseYAML(text) {
                const parts = text.split('results:');
                if (parts.length < 2) return [];
                const resultsBlock = parts[1];
                const items = [];
                let currentItem = {};
                const lines = resultsBlock.split('\\n');
                for (let line of lines) {
                    line = line.trim();
                    if (!line) continue;
                    if (line.startsWith('- ')) {
                        if (Object.keys(currentItem).length > 0) items.push(currentItem);
                        currentItem = {};
                        line = line.substring(2);
                    }
                    const colonIdx = line.indexOf(':');
                    if (colonIdx > -1) {
                        const k = line.substring(0, colonIdx).trim();
                        const v = line.substring(colonIdx + 1).trim();
                        currentItem[k] = v;
                    }
                }
                if (Object.keys(currentItem).length > 0) items.push(currentItem);
                return items;
            }

            function performAnalysis(results, hostname, totalTime, expectedHash) {
                let hashValidation = null;
                if (results && results.length > 0) {
                    const hashes = results.filter(r => r.hash).map(r => r.hash);
                    if (hashes.length > 0) {
                        const allMatch = hashes.every(h => h === hashes[0]);
                        const uniqueHashes = [...new Set(hashes)];
                        hashValidation = {
                            total_ips: results.length,
                            unique_hashes: uniqueHashes.length,
                            all_match: allMatch
                        };
                        if (!allMatch) {
                            hashValidation.mismatches = uniqueHashes.map(hash => ({
                                hash: hash,
                                ips: results.filter(r => r.hash === hash).map(r => r.ip)
                            }));
                        }
                    }
                }
                
                let summaryHTML = '<div class="result-summary">';
                if (hostname) summaryHTML += `<h3>${hostname}</h3>`;
                
                if (results.length > 0) {
                        const timeStr = totalTime ? ` in ${totalTime}s` : '';
                        summaryHTML += `<p class="result-detail">Checked ${results.length} IP${results.length !== 1 ? 's' : ''}${timeStr}</p>`;
                        
                        if (hashValidation) {
                        if (expectedHash) {
                            const normExpected = expectedHash.toLowerCase().trim();
                            const normHashes = results.filter(r => r.hash).map(r => r.hash.toLowerCase());
                            const allMatchExpected = normHashes.every(h => h === normExpected);
                            
                            if (allMatchExpected) {
                                summaryHTML += '<p class="result-status success">✓ All hashes match expected value</p>';
                            } else {
                                const allConsistent = normHashes.every(h => h === normHashes[0]);
                                if (allConsistent) {
                                        summaryHTML += '<p class="result-status error">✗ Hash does not match expected value</p>';
                                        summaryHTML += `<p class="result-detail">Expected: ${expectedHash.substring(0, 16)}...<br>Actual: ${results[0].hash.substring(0, 16)}...</p>`;
                                } else {
                                        summaryHTML += '<p class="result-status error">✗ Hash mismatch detected</p>';
                                        const matchCount = normHashes.filter(h => h === normExpected).length;
                                        if (matchCount > 0) {
                                        summaryHTML += `<p class="result-detail">${matchCount} IP(s) match expectation<br>${results.length - matchCount} IP(s) mismatch</p>`;
                                        } else {
                                        summaryHTML += `<p class="result-detail">No IPs match expected hash</p>`;
                                        }
                                }
                            }
                        } else {
                            if (hashValidation.all_match) {
                                summaryHTML += '<p class="result-status success">✓ All hashes match</p>';
                            } else {
                                summaryHTML += '<p class="result-status error">✗ Hash mismatch detected</p>';
                                summaryHTML += `<p class="result-detail">${hashValidation.unique_hashes} unique hash${hashValidation.unique_hashes !== 1 ? 'es' : ''} found</p>`;
                            }
                        }
                    } else {
                        const successCount = results.filter(r => r.status_code == 200 || r.status_code == 301 || r.status_code == 302).length;
                        const errorCount = results.filter(r => r.error).length;
                        if (errorCount === 0 && successCount > 0) {
                            summaryHTML += '<p class="result-status success">✓ All requests successful</p>';
                        } else if (errorCount > 0) {
                            summaryHTML += `<p class="result-status error">✗ ${errorCount} error${errorCount !== 1 ? 's' : ''}</p>`;
                        } else {
                            summaryHTML += '<p class="result-detail">No content hashes found</p>';
                        }
                    }
                } else {
                    summaryHTML += '<p class="result-status success">✓ Request successful</p>';
                    summaryHTML += '<p class="result-detail">(Content analysis available via JSON/YAML parsing)</p>';
                }
                
                summaryHTML += '</div>';
                return summaryHTML;
            }

            form.addEventListener('submit', async (event) => {
                event.preventDefault();
                const targetUrl = urlInput.value.trim();
                if (!targetUrl) {
                    summary.innerHTML = '<p style="text-align: center; color: var(--accent);">Please provide a URL.</p>';
                    return;
                }

                submitBtn.disabled = true;
                const originalBtnText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<span class="spinner"></span>Running...';
                summary.innerHTML = '<p style="text-align: center; color: var(--muted);">Resolving IPs and fetching content...</p>';
                fullResultsDrawer.style.display = 'none';
                curlCommandDrawer.style.display = 'none';

                try {
                    const paramsObj = {
                        url: targetUrl,
                        format: formatSelect.value,
                        timeout: timeoutInput.value,
                        hash_alg: hashAlgSelect.value
                    };
                    
                    const endpoints = eovEndpointsInput.value.trim();
                    if (endpoints) paramsObj.eov_endpoints = endpoints;

                    const params = new URLSearchParams(paramsObj);
                    const hashValue = hashInput.value.trim();
                    if (hashValue) params.append('hash', hashValue);

                    const apiUrl = window.location.origin + '/v1/eov?' + params.toString();
                    curlCommand.value = `curl '${apiUrl}'`;
                    curlCommandDrawer.style.display = 'block';
                    
                    const resp = await fetch('/v1/eov?' + params.toString());
                    const text = await resp.text();
                    
                    fullResultsSummary.textContent = `Full Results (${formatSelect.value.toUpperCase()})`;
                    output.value = text;
                    fullResultsDrawer.style.display = 'block';

                    if (!resp.ok) {
                            summary.innerHTML = `<p class="result-status error">Request failed (${resp.status})</p>`;
                            return;
                    }

                    let results = [];
                    let hostname = new URL(targetUrl).hostname;
                    let totalTime = null;

                    try {
                        if (formatSelect.value === 'json') {
                            const data = JSON.parse(text);
                            results = data.results || [];
                            hostname = data.hostname;
                            totalTime = data.total_time_seconds;
                            output.value = JSON.stringify(data, null, 2);
                        } else if (formatSelect.value === 'csv') {
                            results = parseCSV(text);
                        } else if (formatSelect.value === 'yaml') {
                            results = parseYAML(text);
                        }
                        
                        summary.innerHTML = performAnalysis(results, hostname, totalTime, hashValue);

                    } catch (parseErr) {
                        console.error(parseErr);
                        summary.innerHTML = `
                            <div class="result-summary">
                                <h3>${hostname}</h3>
                                <p class="result-status success">✓ Request successful</p>
                                <p class="result-detail" style="font-size: 0.8em">Analysis failed (Parse Error)</p>
                            </div>`;
                    }

                } catch (err) {
                    summary.innerHTML = `<p class="result-status error">Request failed: ${err}</p>`;
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalBtnText;
                }
            });

            const piLink = document.getElementById('pi-link');
            piLink.addEventListener('click', (e) => {
                if (!(e.ctrlKey && e.shiftKey)) e.preventDefault();
            });
        </script>
    """
    return Response(render_page("Endpoint Object Validation", ui_html, head_css), mimetype="text/html")

@app.route("/v1/eov")
def v1_eov():
    # 1. Validation
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL required', 'usage': '/v1/eov?url=...'}), 400
        
    hash_alg = request.args.get('hash_alg', 'md5').lower()
    if hash_alg not in HASH_FUNCS:
        return jsonify({'error': f'Unsupported hash: {hash_alg}'}), 400

    parsed = urlparse(url)
    if not parsed.hostname or parsed.hostname in FORBIDDEN_HOSTS:
        return jsonify({'error': 'Invalid hostname'}), 400

    # 2. Setup
    start_epoch = int(time.time())
    start_perf = time.perf_counter()
    timeout = int(request.args.get('timeout', 33))
    scheme = parsed.scheme
    hostname = parsed.hostname
    
    # 3. Execution (Remote vs Local)
    results = []
    ext_endpoints = request.args.get('eov_endpoints', '').strip()
    
    if ext_endpoints:
        # Remote Aggregation
        nodes = [e.strip() for e in ext_endpoints.split(',') if e.strip()]
        params = {'hash': request.args.get('hash'), 'hash_alg': hash_alg, 'timeout': timeout}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as executor:
            futures = {executor.submit(query_external_eov, node, url, params): node for node in nodes}
            for f in concurrent.futures.as_completed(futures):
                results.extend(f.result())
    else:
        # Local Resolution
        try:
            ips = socket.gethostbyname_ex(hostname)[2]
            # Use threading for parallel IP checks
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 20)) as executor:
                futures = {
                    executor.submit(check_single_ip, ip, url, hostname, scheme, timeout, hash_alg, request.args.get('hash')): ip 
                    for ip in ips
                }
                for f in concurrent.futures.as_completed(futures):
                    res = f.result()
                    res['eov_server'] = 'local'
                    results.append(res)
        except Exception as e:
            return jsonify({'error': f'Resolution failed: {e}'}), 500

    # 4. Response Formatting
    results.sort(key=lambda x: (x.get('ip', ''), x.get('eov_server', '')))
    total_time = round(time.perf_counter() - start_perf, 3)
    
    data = {
        'url': url, 'hostname': hostname, 'protocol': 443 if scheme == 'https' else 80,
        'hash_alg': hash_alg, 'expected_hash': request.args.get('hash'),
        'epoch_timestamp': start_epoch, 'total_time_seconds': total_time,
        'results': results
    }
    
    fmt = request.args.get('format', 'json').lower()
    if fmt == 'json':
        return jsonify(data)
    elif fmt == 'yaml':
        return Response(yaml.dump(data), mimetype='text/yaml')
    elif fmt == 'csv':
        out = io.StringIO()
        if results:
            writer = csv.DictWriter(out, fieldnames=sorted(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)
        return Response(out.getvalue(), mimetype='text/csv')
        
    return jsonify({'error': 'Unsupported format'}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)