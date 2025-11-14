"""Tests for ROA payload state parsing."""

import pytest


def test_roa_state_exists(parsed_ccr):
    """Test that ROA payload state is present."""
    assert parsed_ccr.roa_payload_state is not None


def test_roa_state_hash(parsed_ccr):
    """Test ROA payload state hash value."""
    rps = parsed_ccr.roa_payload_state
    # Expected: NzcwOUE0RjJEMUQyRERFMTgwRkE5QjJDQTcwNTU5MTU=
    import base64
    expected_hash = base64.b64decode('NzcwOUE0RjJEMUQyRERFMTgwRkE5QjJDQTcwNTU5MTU=')
    assert rps.hash == expected_hash


def test_roa_payload_count(parsed_ccr):
    """Test total number of ROA prefixes."""
    rps = parsed_ccr.roa_payload_state
    total_prefixes = sum(len(ps.prefixes) for ps in rps.payload_sets)
    # From test vector: 47 prefixes total
    assert total_prefixes == 47


def test_roa_asn_values(parsed_ccr):
    """Test that expected AS numbers are present."""
    rps = parsed_ccr.roa_payload_state
    asns = {ps.asn for ps in rps.payload_sets}
    # From test vector: AS 7, AS 8283, AS 15562
    assert 7 in asns
    assert 8283 in asns
    assert 15562 in asns


def test_roa_as7_prefixes(parsed_ccr):
    """Test AS7 ROA entries."""
    rps = parsed_ccr.roa_payload_state
    as7_sets = [ps for ps in rps.payload_sets if ps.asn == 7]
    assert len(as7_sets) == 1

    as7 = as7_sets[0]
    # Expected prefixes for AS7:
    # 192.35.94.0/24-32, 192.67.43.0/24-32, 194.32.69.0/24-32,
    # 194.32.218.0/23-32, 194.34.138.0/24-32, 194.61.92.0/23-32,
    # 2a0b:3b40::/29-128
    assert len(as7.prefixes) == 7

    prefix_strs = [str(p) for p in as7.prefixes]
    assert '192.35.94.0/24-32' in prefix_strs or '192.35.94.0/24' in prefix_strs
    assert any('2a0b:3b40::' in p for p in prefix_strs)  # IPv6 prefix


def test_roa_ipv4_and_ipv6_mixed(parsed_ccr):
    """Test that ROAs contain both IPv4 and IPv6 prefixes."""
    rps = parsed_ccr.roa_payload_state
    has_ipv4 = False
    has_ipv6 = False

    for ps in rps.payload_sets:
        for prefix in ps.prefixes:
            if ':' in prefix.prefix:
                has_ipv6 = True
            else:
                has_ipv4 = True

    assert has_ipv4, "Should have IPv4 prefixes"
    assert has_ipv6, "Should have IPv6 prefixes"


def test_roa_max_length(parsed_ccr):
    """Test that max_length is properly parsed."""
    rps = parsed_ccr.roa_payload_state
    # From test vector, AS 7 has prefixes with max_length 32
    as7_sets = [ps for ps in rps.payload_sets if ps.asn == 7]
    assert len(as7_sets) == 1

    # Check that some prefixes have max_length
    prefixes_with_maxlen = [p for p in as7_sets[0].prefixes if p.max_length is not None]
    assert len(prefixes_with_maxlen) > 0

    # Check specific values
    for p in prefixes_with_maxlen:
        if ':' not in p.prefix:  # IPv4
            assert p.max_length <= 32
        else:  # IPv6
            assert p.max_length <= 128


def test_roa_as8283_count(parsed_ccr):
    """Test AS8283 has correct number of prefixes."""
    rps = parsed_ccr.roa_payload_state
    as8283_sets = [ps for ps in rps.payload_sets if ps.asn == 8283]
    assert len(as8283_sets) == 1

    # From test vector: AS 8283 has 15 prefixes
    assert len(as8283_sets[0].prefixes) == 15


def test_roa_as15562_count(parsed_ccr):
    """Test AS15562 has correct number of prefixes."""
    rps = parsed_ccr.roa_payload_state
    as15562_sets = [ps for ps in rps.payload_sets if ps.asn == 15562]
    assert len(as15562_sets) == 1

    # From test vector: AS 15562 has 13 prefixes
    assert len(as15562_sets[0].prefixes) == 13


def test_roa_specific_prefix(parsed_ccr):
    """Test specific ROA prefix values."""
    rps = parsed_ccr.roa_payload_state
    # Look for specific prefix from test vector: 192.35.94.0/24-32 AS 7
    as7_sets = [ps for ps in rps.payload_sets if ps.asn == 7]
    prefix_strs = [p.prefix for p in as7_sets[0].prefixes]

    assert any('192.35.94.0/24' in p for p in prefix_strs)
