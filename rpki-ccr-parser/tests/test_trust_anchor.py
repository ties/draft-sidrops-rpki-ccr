"""Tests for trust anchor state parsing."""

import pytest


def test_trust_anchor_state_exists(parsed_ccr):
    """Test that trust anchor state is present."""
    assert parsed_ccr.trust_anchor_state is not None


def test_trust_anchor_state_hash(parsed_ccr):
    """Test trust anchor state hash value."""
    tas = parsed_ccr.trust_anchor_state
    # Full SHA-256 hash (32 bytes)
    expected_hash = bytes.fromhex('b9ba66b2bcd54e4812249f60ed2de9357670cc48ff848f1bc35f5986703de71f')
    assert tas.hash == expected_hash


def test_trust_anchor_count(parsed_ccr):
    """Test number of trust anchor SKIs."""
    tas = parsed_ccr.trust_anchor_state
    # From test vector: 5 trust anchor key IDs
    assert len(tas.skis) == 5


def test_trust_anchor_ski_length(parsed_ccr):
    """Test that all SKIs are 20 bytes."""
    tas = parsed_ccr.trust_anchor_state
    for ski in tas.skis:
        assert len(ski) == 20, f"SKI should be 20 bytes, got {len(ski)}"


def test_trust_anchor_specific_skis(parsed_ccr):
    """Test specific trust anchor SKI values."""
    tas = parsed_ccr.trust_anchor_state
    # From test vector: 0B9CCA90DD0D7A8A37666B19217FE0D84037B7A2, 13D4F24F9A9FCD98DB36F930631808C88F3974BC,
    # E8552B1FD6D1A4F7E404C6D8E5680D1EBC163FC3, EB680F38F5D6C71BB4B106B8BD06585012DA31B6,
    # FC8A9CB3ED184E17D30EEA1E0FA7615CE4B1AF47
    expected_skis = [
        bytes.fromhex('0B9CCA90DD0D7A8A37666B19217FE0D84037B7A2'),
        bytes.fromhex('13D4F24F9A9FCD98DB36F930631808C88F3974BC'),
        bytes.fromhex('E8552B1FD6D1A4F7E404C6D8E5680D1EBC163FC3'),
        bytes.fromhex('EB680F38F5D6C71BB4B106B8BD06585012DA31B6'),
        bytes.fromhex('FC8A9CB3ED184E17D30EEA1E0FA7615CE4B1AF47'),
    ]

    assert set(tas.skis) == set(expected_skis)


def test_trust_anchor_skis_unique(parsed_ccr):
    """Test that all trust anchor SKIs are unique."""
    tas = parsed_ccr.trust_anchor_state
    assert len(tas.skis) == len(set(tas.skis)), "Trust anchor SKIs should be unique"
