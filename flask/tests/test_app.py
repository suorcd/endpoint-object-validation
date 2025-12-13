import pytest
import sys
import os
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