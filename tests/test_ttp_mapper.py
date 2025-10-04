import pytest
import json
import tempfile
import os
from backend.ttp_mapper import TTPMapper


@pytest.fixture
def sample_mappings():
    return {
        "T1078": {
            "name": "Valid Accounts",
            "description": "Test description",
            "mitigation": "Enforce MFA",
            "aws_service": "iam",
            "function": "mitigate_mfa_enforce"
        },
        "T1552": {
            "name": "Unsecured Credentials",
            "description": "Test description",
            "mitigation": "Enable rotation",
            "aws_service": "secretsmanager",
            "function": "mitigate_secrets_rotation"
        }
    }


@pytest.fixture
def temp_mappings_file(sample_mappings):
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_mappings, f)
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


def test_load_mappings(temp_mappings_file, sample_mappings):
    mapper = TTPMapper(temp_mappings_file)
    assert len(mapper.mappings) == 2
    assert mapper.mappings == sample_mappings


def test_get_all_ttps(temp_mappings_file, sample_mappings):
    mapper = TTPMapper(temp_mappings_file)
    ttps = mapper.get_all_ttps()
    assert ttps == sample_mappings


def test_get_ttp(temp_mappings_file):
    mapper = TTPMapper(temp_mappings_file)
    ttp = mapper.get_ttp("T1078")
    assert ttp is not None
    assert ttp["name"] == "Valid Accounts"


def test_get_ttp_not_found(temp_mappings_file):
    mapper = TTPMapper(temp_mappings_file)
    ttp = mapper.get_ttp("T9999")
    assert ttp is None


def test_search_ttps(temp_mappings_file):
    mapper = TTPMapper(temp_mappings_file)
    results = mapper.search_ttps("credentials")
    assert len(results) == 1
    assert "T1552" in results


def test_get_by_service(temp_mappings_file):
    mapper = TTPMapper(temp_mappings_file)
    results = mapper.get_by_service("iam")
    assert len(results) == 1
    assert "T1078" in results
