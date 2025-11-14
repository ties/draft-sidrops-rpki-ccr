"""Tests for ASPA payload state parsing."""

import pytest


def test_aspa_state_exists(parsed_ccr):
    """Test that ASPA payload state is present."""
    assert parsed_ccr.aspa_payload_state is not None


def test_aspa_state_hash(parsed_ccr):
    """Test ASPA payload state hash value."""
    aps = parsed_ccr.aspa_payload_state
    # Full SHA-256 hash (32 bytes)
    expected_hash = bytes.fromhex('7f130142d5de287e544f69b291f4101c0ba1264e8da00b8004c1ecd6e97f0f6e')
    assert aps.hash == expected_hash


def test_aspa_payload_count(parsed_ccr):
    """Test number of ASPA payload sets."""
    aps = parsed_ccr.aspa_payload_state
    # From test vector: 5 ASPA entries
    assert len(aps.payload_sets) == 5


def test_aspa_customer_asns(parsed_ccr):
    """Test that expected customer AS numbers are present."""
    aps = parsed_ccr.aspa_payload_state
    customer_asns = {ps.customer_asn for ps in aps.payload_sets}
    # From test vector: customer: 945, 7719, 11358, 11967, 16909
    assert 945 in customer_asns
    assert 7719 in customer_asns
    assert 11358 in customer_asns
    assert 11967 in customer_asns
    assert 16909 in customer_asns


def test_aspa_as945_providers(parsed_ccr):
    """Test AS945 ASPA entry."""
    aps = parsed_ccr.aspa_payload_state
    as945_sets = [ps for ps in aps.payload_sets if ps.customer_asn == 945]
    assert len(as945_sets) == 1

    as945 = as945_sets[0]
    # From test vector: customer: 945 providers: 1421, 7719
    assert set(as945.provider_asns) == {1421, 7719}


def test_aspa_as7719_providers(parsed_ccr):
    """Test AS7719 ASPA entry."""
    aps = parsed_ccr.aspa_payload_state
    as7719_sets = [ps for ps in aps.payload_sets if ps.customer_asn == 7719]
    assert len(as7719_sets) == 1

    as7719 = as7719_sets[0]
    # From test vector: customer: 7719 providers: 945, 1421, 61138
    assert set(as7719.provider_asns) == {945, 1421, 61138}


def test_aspa_as11358_providers(parsed_ccr):
    """Test AS11358 ASPA entry."""
    aps = parsed_ccr.aspa_payload_state
    as11358_sets = [ps for ps in aps.payload_sets if ps.customer_asn == 11358]
    assert len(as11358_sets) == 1

    as11358 = as11358_sets[0]
    # From test vector: customer: 11358 providers: 835, 924, 6939, 20473, 34927
    assert set(as11358.provider_asns) == {835, 924, 6939, 20473, 34927}


def test_aspa_as11967_providers(parsed_ccr):
    """Test AS11967 ASPA entry."""
    aps = parsed_ccr.aspa_payload_state
    as11967_sets = [ps for ps in aps.payload_sets if ps.customer_asn == 11967]
    assert len(as11967_sets) == 1

    as11967 = as11967_sets[0]
    # From test vector: customer: 11967 providers: 835, 1299, 6939, 34872, 34927, 50917, 58057, 214809, 215828
    assert set(as11967.provider_asns) == {835, 1299, 6939, 34872, 34927, 50917, 58057, 214809, 215828}


def test_aspa_as16909_providers(parsed_ccr):
    """Test AS16909 ASPA entry."""
    aps = parsed_ccr.aspa_payload_state
    as16909_sets = [ps for ps in aps.payload_sets if ps.customer_asn == 16909]
    assert len(as16909_sets) == 1

    as16909 = as16909_sets[0]
    # From test vector: customer: 16909 providers: 6939, 20473, 41051, 52025, 53667, 214481, 401507
    assert set(as16909.provider_asns) == {6939, 20473, 41051, 52025, 53667, 214481, 401507}


def test_aspa_provider_count_varies(parsed_ccr):
    """Test that different ASPAs have different numbers of providers."""
    aps = parsed_ccr.aspa_payload_state
    provider_counts = [len(ps.provider_asns) for ps in aps.payload_sets]

    # Should have variety in provider counts
    assert min(provider_counts) >= 2
    assert max(provider_counts) >= 5
    assert len(set(provider_counts)) > 1  # Not all the same
