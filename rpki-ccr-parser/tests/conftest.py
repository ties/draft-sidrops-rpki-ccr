"""Pytest fixtures for CCR parser tests."""

import pytest
from pathlib import Path

from rpki_ccr_parser import CCRParser


@pytest.fixture
def test_vector_path():
    """Path to the test vector base64 file."""
    # Test vector is in the parent directory of rpki-ccr-parser
    return Path(__file__).parent.parent.parent / 'testvector.b64'


@pytest.fixture
def test_vector_data(test_vector_path):
    """Load the test vector base64 data."""
    with open(test_vector_path, 'r') as f:
        return f.read()


@pytest.fixture
def parsed_ccr(test_vector_data):
    """Parse the test vector and return CCR object."""
    parser = CCRParser()
    return parser.parse_base64(test_vector_data)


@pytest.fixture
def parser():
    """Return a fresh CCRParser instance."""
    return CCRParser()
