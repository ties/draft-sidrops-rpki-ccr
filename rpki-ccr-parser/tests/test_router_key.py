"""Tests for router key state parsing."""

import pytest


def test_router_key_state_exists(parsed_ccr):
    """Test that router key state is present."""
    assert parsed_ccr.router_key_state is not None


def test_router_key_state_hash(parsed_ccr):
    """Test router key state hash value."""
    rks = parsed_ccr.router_key_state
    # Expected: QkE1RkI0NDlDRUZCNkJBMDBGMzYxMjc5NjJBMkVFQTY=
    import base64
    expected_hash = base64.b64decode('QkE1RkI0NDlDRUZCNkJBMDBGMzYxMjc5NjJBMkVFQTY=')
    assert rks.hash == expected_hash


def test_router_key_set_count(parsed_ccr):
    """Test number of router key sets."""
    rks = parsed_ccr.router_key_state
    # From test vector: 1 AS (15562) with 2 keys
    assert len(rks.key_sets) == 1


def test_router_key_total_count(parsed_ccr):
    """Test total number of router keys."""
    rks = parsed_ccr.router_key_state
    total_keys = sum(len(ks.router_keys) for ks in rks.key_sets)
    # From test vector: 2 router keys
    assert total_keys == 2


def test_router_key_as15562(parsed_ccr):
    """Test AS15562 router key set."""
    rks = parsed_ccr.router_key_state
    as15562_sets = [ks for ks in rks.key_sets if ks.asn == 15562]
    assert len(as15562_sets) == 1

    ks = as15562_sets[0]
    assert ks.asn == 15562
    assert len(ks.router_keys) == 2


def test_router_key_specific_skis(parsed_ccr):
    """Test specific router key SKI values."""
    rks = parsed_ccr.router_key_state
    # From test vector:
    # asid:15562 ski:5D4250E2D81D4448D8A29EFCE91D29FF075EC9E2
    # asid:15562 ski:BE889B55D0B737397D75C49F485B858FA98AD11F
    expected_skis = [
        bytes.fromhex('5D4250E2D81D4448D8A29EFCE91D29FF075EC9E2'),
        bytes.fromhex('BE889B55D0B737397D75C49F485B858FA98AD11F'),
    ]

    as15562_sets = [ks for ks in rks.key_sets if ks.asn == 15562]
    actual_skis = [rk.ski for rk in as15562_sets[0].router_keys]

    assert set(actual_skis) == set(expected_skis)


def test_router_key_ski_length(parsed_ccr):
    """Test that all router key SKIs are 20 bytes."""
    rks = parsed_ccr.router_key_state
    for ks in rks.key_sets:
        for rk in ks.router_keys:
            assert len(rk.ski) == 20, f"Router key SKI should be 20 bytes, got {len(rk.ski)}"


def test_router_key_spki_present(parsed_ccr):
    """Test that SPKIs are present and non-empty."""
    rks = parsed_ccr.router_key_state
    for ks in rks.key_sets:
        for rk in ks.router_keys:
            assert rk.spki is not None
            assert len(rk.spki) > 0, "SPKI should not be empty"


def test_router_key_spki_base64_values(parsed_ccr):
    """Test specific SPKI values from test vector."""
    rks = parsed_ccr.router_key_state
    # From test vector, the SPKIs are:
    # pubkey:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgFcjQ/g//LAQerAH2Mpp+GucoDAGBbhIqD33wNPsXxnAGb+mtZ7XQrVO9DQ6UlAShtig5+QfEKpTtFgiqfiAFQ==
    # pubkey:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4FxJr0n2bux1uX1Evl+QWwZYvIadPjLuFX2mxqKuAGUhKnr7VLLDgrE++l9p5eH2kWTNVAN22FUU3db/RKpE2w==

    import base64
    expected_spkis = [
        base64.b64decode('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgFcjQ/g//LAQerAH2Mpp+GucoDAGBbhIqD33wNPsXxnAGb+mtZ7XQrVO9DQ6UlAShtig5+QfEKpTtFgiqfiAFQ=='),
        base64.b64decode('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4FxJr0n2bux1uX1Evl+QWwZYvIadPjLuFX2mxqKuAGUhKnr7VLLDgrE++l9p5eH2kWTNVAN22FUU3db/RKpE2w=='),
    ]

    as15562_sets = [ks for ks in rks.key_sets if ks.asn == 15562]
    actual_spkis = [rk.spki for rk in as15562_sets[0].router_keys]

    # The SPKIs should match (order may vary)
    assert set(actual_spkis) == set(expected_spkis)
