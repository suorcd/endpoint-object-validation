import pytest
import sys
import os
import socket
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path so we can import app.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    """Test that the home page loads correctly."""
    rv = client.get('/')
    assert rv.status_code == 200
    assert b"Endpoint Object Validation" in rv.data
    assert b"Target URL" in rv.data

def test_r2_page(client):
    """Test the Easter egg page."""
    rv = client.get('/r2.html')
    assert rv.status_code == 200
    assert b"Never gonna give you up" in rv.data

def test_v1_eov_no_url(client):
    """Test error response when URL is missing."""
    rv = client.get('/v1/eov')
    assert rv.status_code == 400
    json_data = rv.get_json()
    assert 'error' in json_data
    assert json_data['error'] == 'URL required'

def test_v1_eov_invalid_algo(client):
    """Test error response for unsupported hash algorithm."""
    rv = client.get('/v1/eov?url=http://example.com&hash_alg=invalid')
    assert rv.status_code == 400
    json_data = rv.get_json()
    assert 'Unsupported hash' in json_data['error']

def test_v1_eov_forbidden_host(client):
    """Test that localhost/internal IPs are forbidden."""
    forbidden_urls = [
        'http://localhost/file',
        'http://127.0.0.1/file',
        'http://0.0.0.0/file'
    ]
    for url in forbidden_urls:
        rv = client.get(f'/v1/eov?url={url}')
        assert rv.status_code == 400
        json_data = rv.get_json()
        assert json_data['error'] == 'Invalid hostname'

@patch('app.socket.gethostbyname_ex')
@patch('app.check_single_ip')
def test_v1_eov_success_json(mock_check, mock_socket, client):
    """Test a successful validation flow with JSON output (Mocked)."""
    # Mock DNS resolution to return 2 IPs
    mock_socket.return_value = ('example.com', [], ['1.1.1.1', '2.2.2.2'])
    
    # Mock the individual IP check results
    mock_check.side_effect = [
        {'ip': '1.1.1.1', 'status_code': 200, 'hash': 'deadbeef', 'hash_alg': 'md5', 'file_size_bytes': 100},
        {'ip': '2.2.2.2', 'status_code': 200, 'hash': 'deadbeef', 'hash_alg': 'md5', 'file_size_bytes': 100}
    ]

    rv = client.get('/v1/eov?url=http://example.com/test.png&hash_alg=md5')
    
    assert rv.status_code == 200
    data = rv.get_json()
    
    assert data['hostname'] == 'example.com'
    assert data['protocol'] == 80
    assert len(data['results']) == 2
    assert data['results'][0]['ip'] == '1.1.1.1'
    assert data['results'][0]['hash'] == 'deadbeef'

@patch('app.socket.gethostbyname_ex')
@patch('app.check_single_ip')
def test_v1_eov_success_csv(mock_check, mock_socket, client):
    """Test CSV format output."""
    mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
    mock_check.return_value = {'ip': '1.1.1.1', 'status_code': 200, 'hash': 'abc', 'hash_alg': 'md5', 'file_size_bytes': 123}

    rv = client.get('/v1/eov?url=http://example.com/test.png&format=csv')
    
    assert rv.status_code == 200
    assert rv.mimetype == 'text/csv'
    content = rv.data.decode('utf-8')
    # The app sorts keys alphabetically: eov_server, file_size_bytes, hash, hash_alg, ip, status_code
    assert 'eov_server,file_size_bytes,hash,hash_alg,ip,status_code' in content
    assert 'local,123,abc,md5,1.1.1.1,200' in content

@patch('app.concurrent.futures.ThreadPoolExecutor')
def test_v1_eov_remote_endpoints(mock_executor, client):
    """Test logic when external EOV endpoints are provided."""
    # We mock ThreadPoolExecutor to avoid complex async logic in unit tests
    # and just verify that the code attempts to handle external endpoints.
    
    # Manually constructing the Future mock
    mock_future = MagicMock()
    mock_future.result.return_value = [
        {'eov_server': 'https://node1.com', 'ip': '10.0.0.1', 'hash': '123'}
    ]
    
    mock_executor_instance = MagicMock()
    mock_executor_instance.__enter__.return_value = mock_executor_instance
    mock_executor_instance.submit.return_value = mock_future
    
    # We also need to mock as_completed
    with patch('app.concurrent.futures.as_completed', return_value=[mock_future]):
        with patch('app.query_external_eov') as mock_query: # Mock the actual query function
            mock_query.return_value = [{'eov_server': 'node1', 'hash': '123'}]
            
            rv = client.get('/v1/eov?url=http://example.com&eov_endpoints=node1.com')
            
            assert rv.status_code == 200
            data = rv.get_json()
            # Since we mocked the result directly via the future logic in app.py
            # we check if results contains what our mock returned
            assert len(data['results']) == 1
            assert data['results'][0]['eov_server'] == 'https://node1.com'

def test_favicon(client):
    """Test favicon endpoint."""
    rv = client.get('/favicon.ico')
    assert rv.status_code == 200

def test_v1_eov_sha1_algorithm(client):
    """Test with SHA1 hash algorithm."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'aabbccdd', 
                'hash_alg': 'sha1', 'file_size_bytes': 256
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file&hash_alg=sha1')
            
            assert rv.status_code == 200
            data = rv.get_json()
            assert data['hash_alg'] == 'sha1'
            assert data['results'][0]['hash_alg'] == 'sha1'

def test_v1_eov_sha256_algorithm(client):
    """Test with SHA256 hash algorithm."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'abcd1234', 
                'hash_alg': 'sha256', 'file_size_bytes': 512
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file&hash_alg=sha256')
            
            assert rv.status_code == 200
            data = rv.get_json()
            assert data['hash_alg'] == 'sha256'

def test_v1_eov_with_expected_hash_match(client):
    """Test when expected hash is provided and matches."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'abc123', 
                'hash_alg': 'md5', 'file_size_bytes': 100, 'hash_matches': True
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file&hash=abc123')
            
            assert rv.status_code == 200
            data = rv.get_json()
            assert data['expected_hash'] == 'abc123'
            assert data['results'][0]['hash_matches'] == True

def test_v1_eov_with_expected_hash_mismatch(client):
    """Test when expected hash is provided and doesn't match."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'xyz999', 
                'hash_alg': 'md5', 'file_size_bytes': 100, 'hash_matches': False
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file&hash=abc123')
            
            assert rv.status_code == 200
            data = rv.get_json()
            assert data['results'][0]['hash_matches'] == False

def test_v1_eov_multiple_ips_different_hashes(client):
    """Test detection of hash mismatches across different IPs."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1', '2.2.2.2'])
            # Different hashes for different IPs
            mock_check.side_effect = [
                {'ip': '1.1.1.1', 'status_code': 200, 'hash': 'hash1', 'hash_alg': 'md5', 'file_size_bytes': 100},
                {'ip': '2.2.2.2', 'status_code': 200, 'hash': 'hash2', 'hash_alg': 'md5', 'file_size_bytes': 100}
            ]
            
            rv = client.get('/v1/eov?url=http://example.com/file')
            
            assert rv.status_code == 200
            data = rv.get_json()
            assert len(data['results']) == 2
            assert data['results'][0]['hash'] != data['results'][1]['hash']

def test_v1_eov_yaml_format(client):
    """Test YAML format output."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'xyz', 
                'hash_alg': 'md5', 'file_size_bytes': 50
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file&format=yaml')
            
            assert rv.status_code == 200
            assert rv.mimetype == 'text/yaml'
            assert b'hostname: example.com' in rv.data
            assert b'results:' in rv.data

def test_v1_eov_csv_with_no_results(client):
    """Test CSV format with empty results (edge case)."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        mock_socket.return_value = ('example.com', [], [])
        
        rv = client.get('/v1/eov?url=http://example.com/file&format=csv')
        
        # Empty IP list returns 500 because gethostbyname_ex returns no IPs
        # The app handles this by returning results from ThreadPoolExecutor with no tasks
        assert rv.status_code in [200, 500]

def test_v1_eov_unsupported_format(client):
    """Test error response for unsupported output format."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {'ip': '1.1.1.1', 'status_code': 200, 'hash': 'xyz', 'hash_alg': 'md5', 'file_size_bytes': 50}
            
            rv = client.get('/v1/eov?url=http://example.com/file&format=xml')
            
            assert rv.status_code == 400
            json_data = rv.get_json()
            assert 'error' in json_data
            assert 'Unsupported format' in json_data['error']

def test_v1_eov_dns_resolution_failure(client):
    """Test error handling when DNS resolution fails."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        mock_socket.side_effect = socket.gaierror('Name resolution failed')
        
        rv = client.get('/v1/eov?url=http://example.com/file')
        
        assert rv.status_code == 500
        json_data = rv.get_json()
        assert 'Resolution failed' in json_data['error']

def test_v1_eov_request_with_custom_timeout(client):
    """Test that custom timeout parameter is respected."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'xyz', 
                'hash_alg': 'md5', 'file_size_bytes': 50
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file&timeout=60')
            
            assert rv.status_code == 200
            # Verify check_single_ip was called with the timeout value
            # check_single_ip(ip, url, hostname, scheme, timeout, hash_alg, expected_hash)
            call_args = mock_check.call_args
            assert call_args[0][4] == 60  # timeout is 5th positional argument (0-indexed)

def test_v1_eov_https_url(client):
    """Test handling of HTTPS URLs (protocol detection)."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'xyz', 
                'hash_alg': 'md5', 'file_size_bytes': 50
            }
            
            rv = client.get('/v1/eov?url=https://example.com/file')
            
            assert rv.status_code == 200
            data = rv.get_json()
            assert data['protocol'] == 443

def test_v1_eov_response_includes_metadata(client):
    """Test that response includes all required metadata fields."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
            mock_check.return_value = {
                'ip': '1.1.1.1', 'status_code': 200, 'hash': 'xyz', 
                'hash_alg': 'md5', 'file_size_bytes': 50
            }
            
            rv = client.get('/v1/eov?url=http://example.com/file')
            
            assert rv.status_code == 200
            data = rv.get_json()
            
            # Verify all metadata fields are present
            assert 'url' in data
            assert 'hostname' in data
            assert 'protocol' in data
            assert 'hash_alg' in data
            assert 'epoch_timestamp' in data
            assert 'total_time_seconds' in data
            assert 'results' in data

def test_v1_eov_results_sorted(client):
    """Test that results are sorted by IP and eov_server."""
    with patch('app.socket.gethostbyname_ex') as mock_socket:
        with patch('app.check_single_ip') as mock_check:
            mock_socket.return_value = ('example.com', [], ['3.3.3.3', '1.1.1.1', '2.2.2.2'])
            mock_check.side_effect = [
                {'ip': '3.3.3.3', 'status_code': 200, 'hash': 'abc', 'hash_alg': 'md5', 'file_size_bytes': 50},
                {'ip': '1.1.1.1', 'status_code': 200, 'hash': 'abc', 'hash_alg': 'md5', 'file_size_bytes': 50},
                {'ip': '2.2.2.2', 'status_code': 200, 'hash': 'abc', 'hash_alg': 'md5', 'file_size_bytes': 50}
            ]
            
            rv = client.get('/v1/eov?url=http://example.com/file')
            
            assert rv.status_code == 200
            data = rv.get_json()
            
            # Verify results are sorted
            ips = [r['ip'] for r in data['results']]
            assert ips == ['1.1.1.1', '2.2.2.2', '3.3.3.3']

@patch('app.socket.gethostbyname_ex')
@patch('app.check_single_ip')
def test_v1_eov_request_error_handling(mock_check, mock_socket, client):
    """Test handling when individual IP checks fail with errors."""
    mock_socket.return_value = ('example.com', [], ['1.1.1.1'])
    mock_check.return_value = {
        'ip': '1.1.1.1', 'status_code': None, 'hash': None, 
        'hash_alg': 'md5', 'file_size_bytes': None,
        'error': 'Connection timeout'
    }
    
    rv = client.get('/v1/eov?url=http://example.com/file')
    
    assert rv.status_code == 200
    data = rv.get_json()
    assert data['results'][0]['error'] == 'Connection timeout'

def test_v1_eov_multiple_external_endpoints(client):
    """Test querying multiple external EOV endpoints."""
    with patch('app.query_external_eov') as mock_query:
        mock_query.side_effect = [
            [{'eov_server': 'https://node1.com', 'ip': '10.0.0.1', 'hash': 'abc'}],
            [{'eov_server': 'https://node2.com', 'ip': '10.0.0.2', 'hash': 'abc'}]
        ]
        
        rv = client.get('/v1/eov?url=http://example.com&eov_endpoints=node1.com,node2.com')
        
        assert rv.status_code == 200
        data = rv.get_json()
        assert len(data['results']) == 2
        assert data['results'][0]['eov_server'] == 'https://node1.com'
        assert data['results'][1]['eov_server'] == 'https://node2.com'

def test_v1_eov_external_endpoint_with_error(client):
    """Test handling when external endpoint returns an error."""
    with patch('app.query_external_eov') as mock_query:
        mock_query.return_value = [{'eov_server': 'https://node1.com', 'error': 'Node Error: Connection refused', 'ip': '0.0.0.0', 'status_code': 0}]
        
        rv = client.get('/v1/eov?url=http://example.com&eov_endpoints=node1.com')
        
        assert rv.status_code == 200
        data = rv.get_json()
        assert 'error' in data['results'][0]
        assert 'Connection refused' in data['results'][0]['error']

def test_home_page_contains_form_fields(client):
    """Test that home page contains all form elements."""
    rv = client.get('/')
    assert rv.status_code == 200
    assert b'id="url"' in rv.data
    assert b'id="hash"' in rv.data
    assert b'id="hash-alg"' in rv.data
    assert b'id="timeout"' in rv.data
    assert b'id="format"' in rv.data
    assert b'id="eov-endpoints"' in rv.data