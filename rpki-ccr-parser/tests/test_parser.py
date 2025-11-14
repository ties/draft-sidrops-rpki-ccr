"""Tests for CCR parser."""

import pytest
from datetime import datetime

from rpki_ccr_parser import CCRParser


def test_parser_parse_base64(test_vector_data, parser):
    """Test parsing base64-encoded CCR."""
    ccr = parser.parse_base64(test_vector_data)
    assert ccr is not None
    assert ccr.version == 0


def test_parser_parse_file(test_vector_path, parser):
    """Test parsing CCR from file."""
    # Create a DER version first
    import base64
    from pathlib import Path

    with open(test_vector_path, 'r') as f:
        b64_data = f.read()

    der_data = base64.b64decode(''.join(b64_data.split()))

    # Write to temp file
    temp_path = Path(test_vector_path).parent / 'temp_test.der'
    with open(temp_path, 'wb') as f:
        f.write(der_data)

    try:
        ccr = parser.parse_file(temp_path)
        assert ccr is not None
        assert ccr.version == 0
    finally:
        # Clean up
        temp_path.unlink(missing_ok=True)


def test_ccr_basic_fields(parsed_ccr):
    """Test basic CCR fields."""
    assert parsed_ccr.version == 0
    assert parsed_ccr.hash_algorithm == '2.16.840.1.101.3.4.2.1'  # SHA-256 OID
    assert isinstance(parsed_ccr.produced_at, datetime)
    # Expected: Sun 12 Oct 2025 22:37:05 +0000
    assert parsed_ccr.produced_at.year == 2025
    assert parsed_ccr.produced_at.month == 10
    assert parsed_ccr.produced_at.day == 12
    assert parsed_ccr.produced_at.hour == 22
    assert parsed_ccr.produced_at.minute == 37
    assert parsed_ccr.produced_at.second == 5


def test_ccr_has_all_states(parsed_ccr):
    """Test that CCR has all expected state types."""
    assert parsed_ccr.manifest_state is not None
    assert parsed_ccr.roa_payload_state is not None
    assert parsed_ccr.aspa_payload_state is not None
    assert parsed_ccr.trust_anchor_state is not None
    assert parsed_ccr.router_key_state is not None


def test_malformed_input(parser):
    """Test that malformed input raises an error."""
    with pytest.raises(Exception):
        parser.parse_base64("not valid base64!")

    with pytest.raises(Exception):
        parser.parse_bytes(b"not valid DER!")
