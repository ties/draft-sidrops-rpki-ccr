"""Tests for manifest state parsing."""

import pytest


def test_manifest_state_exists(parsed_ccr):
    """Test that manifest state is present."""
    assert parsed_ccr.manifest_state is not None


def test_manifest_instance_count(parsed_ccr):
    """Test that there are 7 manifest instances."""
    ms = parsed_ccr.manifest_state
    assert len(ms.instances) == 7


def test_manifest_state_hash(parsed_ccr):
    """Test manifest state hash value."""
    ms = parsed_ccr.manifest_state
    # Expected: QTE0QTY4QjMxREE2QTIzQkY2RDkwRTA1NTJGQ0JBRUE=
    expected_hash = bytes.fromhex('41343141363842333144413641323342463644393045303535324643424145QUE='.replace('QUE=', ''))
    # The hash in the test vector decode is base64 encoded
    import base64
    expected_hash = base64.b64decode('QTE0QTY4QjMxREE2QTIzQkY2RDkwRTA1NTJGQ0JBRUE=')
    assert ms.hash == expected_hash


def test_manifest_instances_fields(parsed_ccr):
    """Test that each manifest instance has required fields."""
    ms = parsed_ccr.manifest_state
    for mi in ms.instances:
        assert mi.hash is not None
        assert len(mi.hash) > 0
        assert mi.size >= 1000  # Minimum size constraint
        assert mi.aki is not None
        assert len(mi.aki) == 20  # SKI is 20 bytes
        assert mi.manifest_number >= 0
        assert mi.this_update is not None
        assert len(mi.locations) >= 1


def test_specific_manifest_instance(parsed_ccr):
    """Test specific manifest instance values."""
    ms = parsed_ccr.manifest_state
    # First manifest from test vector:
    # hash:AAAcOjvS+bajULr7A6fVPnJ94rQnS1QMmIbEly8CfUY= size:2072 aki:85B611A0B7D4334B7A2395E8CCE7B0E3C9B838E8
    mi = ms.instances[0]
    assert mi.size == 2072
    expected_aki = bytes.fromhex('85B611A0B7D4334B7A2395E8CCE7B0E3C9B838E8')
    assert mi.aki == expected_aki
    assert 'rsync://rpki.ripe.net' in mi.locations[0]


def test_manifest_subordinates(parsed_ccr):
    """Test manifests with subordinates."""
    ms = parsed_ccr.manifest_state
    # From test vector, the 4th manifest has subordinates:
    # subordinates:750FD3BA0F6C08563CDDBE911979FB122797649C
    manifests_with_subs = [mi for mi in ms.instances if mi.subordinates is not None]
    assert len(manifests_with_subs) >= 3  # At least 3 manifests have subordinates

    # Check specific subordinate
    for mi in ms.instances:
        if mi.subordinates and len(mi.subordinates) > 0:
            for sub in mi.subordinates:
                assert len(sub) == 20  # SKI is 20 bytes


def test_manifest_locations_are_rsync(parsed_ccr):
    """Test that manifest locations are rsync URLs."""
    ms = parsed_ccr.manifest_state
    for mi in ms.instances:
        for loc in mi.locations:
            assert loc.startswith('rsync://'), f"Expected rsync URL, got: {loc}"
