"""Data models for RPKI Canonical Cache Representation (CCR)."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ManifestInstance:
    """Represents a single manifest instance."""
    hash: bytes
    size: int
    aki: bytes
    manifest_number: int
    this_update: datetime
    locations: list[str]
    subordinates: Optional[list[bytes]] = None

    def __str__(self) -> str:
        """String representation."""
        hash_str = self.hash.hex().upper()
        aki_str = self.aki.hex().upper()
        locations_str = ', '.join(self.locations)
        result = f"ManifestInstance(hash={hash_str}, size={self.size}, aki={aki_str}, "
        result += f"seqnum={self.manifest_number:X}, thisUpdate={self.this_update.isoformat()}, "
        result += f"locations=[{locations_str}]"
        if self.subordinates:
            subs = ', '.join(s.hex().upper() for s in self.subordinates)
            result += f", subordinates=[{subs}]"
        result += ")"
        return result


@dataclass
class ManifestState:
    """Represents the manifest state."""
    instances: list[ManifestInstance]
    most_recent_update: datetime
    hash: bytes

    def __str__(self) -> str:
        """String representation."""
        return f"ManifestState(instances={len(self.instances)}, hash={self.hash.hex().upper()})"


@dataclass
class IPPrefix:
    """Represents an IP prefix with optional max length."""
    prefix: str
    max_length: Optional[int] = None

    def __str__(self) -> str:
        """String representation."""
        if self.max_length is not None:
            return f"{self.prefix}-{self.max_length}"
        return self.prefix


@dataclass
class ROAPayloadSet:
    """Represents a ROA payload set."""
    asn: int
    prefixes: list[IPPrefix]

    def __str__(self) -> str:
        """String representation."""
        prefixes_str = ', '.join(str(p) for p in self.prefixes)
        return f"ROAPayloadSet(AS{self.asn}: {prefixes_str})"


@dataclass
class ROAPayloadState:
    """Represents the ROA payload state."""
    payload_sets: list[ROAPayloadSet]
    hash: bytes

    def __str__(self) -> str:
        """String representation."""
        total_prefixes = sum(len(ps.prefixes) for ps in self.payload_sets)
        return f"ROAPayloadState(sets={len(self.payload_sets)}, prefixes={total_prefixes}, hash={self.hash.hex().upper()})"


@dataclass
class ASPAPayloadSet:
    """Represents an ASPA payload set."""
    customer_asn: int
    provider_asns: list[int]

    def __str__(self) -> str:
        """String representation."""
        providers = ', '.join(str(asn) for asn in self.provider_asns)
        return f"ASPAPayloadSet(customer=AS{self.customer_asn}, providers=[{providers}])"


@dataclass
class ASPAPayloadState:
    """Represents the ASPA payload state."""
    payload_sets: list[ASPAPayloadSet]
    hash: bytes

    def __str__(self) -> str:
        """String representation."""
        return f"ASPAPayloadState(sets={len(self.payload_sets)}, hash={self.hash.hex().upper()})"


@dataclass
class TrustAnchorState:
    """Represents the trust anchor state."""
    skis: list[bytes]
    hash: bytes

    def __str__(self) -> str:
        """String representation."""
        skis_str = ', '.join(ski.hex().upper() for ski in self.skis)
        return f"TrustAnchorState(skis=[{skis_str}], hash={self.hash.hex().upper()})"


@dataclass
class RouterKey:
    """Represents a router key."""
    ski: bytes
    spki: bytes

    def __str__(self) -> str:
        """String representation."""
        return f"RouterKey(ski={self.ski.hex().upper()}, spki_len={len(self.spki)})"


@dataclass
class RouterKeySet:
    """Represents a router key set for an AS."""
    asn: int
    router_keys: list[RouterKey]

    def __str__(self) -> str:
        """String representation."""
        return f"RouterKeySet(AS{self.asn}, keys={len(self.router_keys)})"


@dataclass
class RouterKeyState:
    """Represents the router key state."""
    key_sets: list[RouterKeySet]
    hash: bytes

    def __str__(self) -> str:
        """String representation."""
        total_keys = sum(len(ks.router_keys) for ks in self.key_sets)
        return f"RouterKeyState(sets={len(self.key_sets)}, keys={total_keys}, hash={self.hash.hex().upper()})"


@dataclass
class CCRObject:
    """Represents the complete CCR object."""
    version: int
    hash_algorithm: str
    produced_at: datetime
    manifest_state: Optional[ManifestState] = None
    roa_payload_state: Optional[ROAPayloadState] = None
    aspa_payload_state: Optional[ASPAPayloadState] = None
    trust_anchor_state: Optional[TrustAnchorState] = None
    router_key_state: Optional[RouterKeyState] = None

    def __str__(self) -> str:
        """String representation."""
        parts = [f"CCRObject(version={self.version}, hash_alg={self.hash_algorithm}, produced_at={self.produced_at.isoformat()})"]
        if self.manifest_state:
            parts.append(f"  Manifests: {len(self.manifest_state.instances)} instances")
        if self.roa_payload_state:
            total = sum(len(ps.prefixes) for ps in self.roa_payload_state.payload_sets)
            parts.append(f"  ROAs: {total} prefixes")
        if self.aspa_payload_state:
            parts.append(f"  ASPAs: {len(self.aspa_payload_state.payload_sets)} sets")
        if self.trust_anchor_state:
            parts.append(f"  Trust Anchors: {len(self.trust_anchor_state.skis)} SKIs")
        if self.router_key_state:
            total = sum(len(ks.router_keys) for ks in self.router_key_state.key_sets)
            parts.append(f"  Router Keys: {total} keys")
        return '\n'.join(parts)
