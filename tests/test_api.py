import pytest
from backend.app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_health_check(client):
    response = client.get('/status')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert data['service'] == 'CloudMitigator API'


def test_get_ttps(client):
    response = client.get('/ttps')
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, dict)
    assert len(data) > 0


def test_get_ttps_with_search(client):
    response = client.get('/ttps?search=valid')
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, dict)


def test_get_specific_ttp(client):
    response = client.get('/ttps/T1078')
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == 'Valid Accounts'


def test_get_nonexistent_ttp(client):
    response = client.get('/ttps/T9999')
    assert response.status_code == 404


def test_get_logs(client):
    response = client.get('/logs')
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
