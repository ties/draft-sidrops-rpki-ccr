"""Parser for RPKI Canonical Cache Representation (CCR) files."""

import base64
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from pyasn1.codec.der import decoder
from pyasn1.type import univ

from . import asn1_schema
from . import models
from . import utils


class CCRParser:
    """Parser for CCR files."""

    def __init__(self):
        """Initialize the parser."""
        self._ccr_data: Optional[bytes] = None
        self._ccr_asn1: Optional[asn1_schema.RpkiCanonicalCacheRepresentation] = None

    def parse_file(self, path: Union[str, Path]) -> models.CCRObject:
        """
        Parse a CCR file.

        Args:
            path: Path to the CCR file (DER encoded)

        Returns:
            Parsed CCR object
        """
        with open(path, 'rb') as f:
            data = f.read()
        return self.parse_bytes(data)

    def parse_base64(self, b64_string: str) -> models.CCRObject:
        """
        Parse a base64-encoded CCR.

        Args:
            b64_string: Base64-encoded CCR data

        Returns:
            Parsed CCR object
        """
        data = utils.decode_base64(b64_string)
        return self.parse_bytes(data)

    def parse_bytes(self, data: bytes) -> models.CCRObject:
        """
        Parse CCR from bytes.

        Args:
            data: DER-encoded CCR data

        Returns:
            Parsed CCR object
        """
        self._ccr_data = data

        # First, decode the outer structure (EncapsulatedContentInfo or direct CCR)
        try:
            # Try to decode as EncapsulatedContentInfo first
            content_info, remainder = decoder.decode(data, asn1Spec=asn1_schema.EncapsulatedContentInfo())
            if remainder:
                raise ValueError(f"Unexpected trailing data: {len(remainder)} bytes")

            # Extract the eContent
            if content_info['eContent'].hasValue():
                ccr_data = bytes(content_info['eContent'])
            else:
                raise ValueError("No eContent in EncapsulatedContentInfo")

        except Exception:
            # If that fails, try to decode directly as CCR
            ccr_data = data

        # Decode the CCR structure
        ccr, remainder = decoder.decode(ccr_data, asn1Spec=asn1_schema.RpkiCanonicalCacheRepresentation())
        if remainder:
            raise ValueError(f"Unexpected trailing data: {len(remainder)} bytes")

        self._ccr_asn1 = ccr

        # Parse the CCR structure
        return self._parse_ccr(ccr)

    def _parse_ccr(self, ccr: asn1_schema.RpkiCanonicalCacheRepresentation) -> models.CCRObject:
        """Parse the main CCR structure."""
        # Extract version
        version = int(ccr['version']) if ccr['version'].hasValue() else 0

        # Extract hash algorithm (now just an OID)
        hash_alg_oid = ccr['hashAlg']
        hash_alg = utils.oid_to_string(hash_alg_oid)

        # Extract producedAt timestamp
        produced_at = utils.parse_generalized_time(str(ccr['producedAt']))

        # Parse optional components
        manifest_state = None
        if ccr['mfts'].hasValue():
            manifest_state = self._parse_manifest_state(ccr['mfts'])

        roa_payload_state = None
        if ccr['vrps'].hasValue():
            roa_payload_state = self._parse_roa_payload_state(ccr['vrps'])

        aspa_payload_state = None
        if ccr['vaps'].hasValue():
            aspa_payload_state = self._parse_aspa_payload_state(ccr['vaps'])

        trust_anchor_state = None
        if ccr['tas'].hasValue():
            trust_anchor_state = self._parse_trust_anchor_state(ccr['tas'])

        router_key_state = None
        if ccr['rks'].hasValue():
            router_key_state = self._parse_router_key_state(ccr['rks'])

        return models.CCRObject(
            version=version,
            hash_algorithm=hash_alg,
            produced_at=produced_at,
            manifest_state=manifest_state,
            roa_payload_state=roa_payload_state,
            aspa_payload_state=aspa_payload_state,
            trust_anchor_state=trust_anchor_state,
            router_key_state=router_key_state
        )

    def _parse_manifest_state(self, mfts: asn1_schema.ManifestState) -> models.ManifestState:
        """Parse manifest state."""
        instances = []
        for mi in mfts['mis']:
            instance = self._parse_manifest_instance(mi)
            instances.append(instance)

        most_recent = utils.parse_generalized_time(str(mfts['mostRecentUpdate']))
        hash_value = bytes(mfts['hash'])

        return models.ManifestState(
            instances=instances,
            most_recent_update=most_recent,
            hash=hash_value
        )

    def _parse_manifest_instance(self, mi: asn1_schema.ManifestInstance) -> models.ManifestInstance:
        """Parse a single manifest instance."""
        hash_value = bytes(mi['hash'])
        size = int(mi['size'])
        aki = bytes(mi['aki'])
        manifest_number = int(mi['manifestNumber'])
        this_update = utils.parse_generalized_time(str(mi['thisUpdate']))

        # Parse locations
        locations = []
        for loc in mi['locations']:
            # Extract the accessLocation from AccessDescription
            access_loc = loc['accessLocation']
            location_str = utils.parse_access_location(bytes(access_loc))
            locations.append(location_str)

        # Parse subordinates if present
        subordinates = None
        if mi['subordinates'].hasValue():
            subordinates = [bytes(ski) for ski in mi['subordinates']]

        return models.ManifestInstance(
            hash=hash_value,
            size=size,
            aki=aki,
            manifest_number=manifest_number,
            this_update=this_update,
            locations=locations,
            subordinates=subordinates
        )

    def _parse_roa_payload_state(self, vrps: asn1_schema.ROAPayloadState) -> models.ROAPayloadState:
        """Parse ROA payload state."""
        payload_sets = []
        for rps in vrps['rps']:
            payload_set = self._parse_roa_payload_set(rps)
            payload_sets.append(payload_set)

        hash_value = bytes(vrps['hash'])

        return models.ROAPayloadState(
            payload_sets=payload_sets,
            hash=hash_value
        )

    def _parse_roa_payload_set(self, rps: asn1_schema.ROAPayloadSet) -> models.ROAPayloadSet:
        """Parse a single ROA payload set."""
        asn = int(rps['asID'])
        prefixes = []

        for ip_addr_family in rps['ipAddrBlocks']:
            afi_bytes = bytes(ip_addr_family['addressFamily'])
            afi = utils.parse_afi_from_octets(afi_bytes)

            for roa_ip_addr in ip_addr_family['addresses']:
                prefix = self._parse_roa_ip_address(roa_ip_addr, afi)
                prefixes.append(prefix)

        return models.ROAPayloadSet(
            asn=asn,
            prefixes=prefixes
        )

    def _parse_roa_ip_address(self, roa_ip: asn1_schema.ROAIPAddress, afi: int) -> models.IPPrefix:
        """Parse a ROA IP address."""
        # Get the address bit string
        addr_bits = roa_ip['address']

        # pyasn1 BitString: convert to int to get the bit pattern
        # len() gives us the number of significant bits (prefix length)
        if len(addr_bits) > 0:
            addr_int = int(addr_bits)
            bit_length = len(addr_bits)

            # LEFT-align the bits to byte boundary
            # For N bits, we need to shift left by (8 - N%8) if N%8 != 0
            byte_length = (bit_length + 7) // 8
            bits_to_pad = (byte_length * 8) - bit_length
            addr_int_aligned = addr_int << bits_to_pad

            # Convert to bytes (big-endian)
            addr_bytes = addr_int_aligned.to_bytes(byte_length, byteorder='big')
        else:
            addr_bytes = b''
            bit_length = 0

        # Convert to IP prefix
        prefix_str = utils.bits_to_ip_prefix(addr_bytes, bit_length, afi)

        # Get max length if present
        max_length = None
        if roa_ip['maxLength'].hasValue():
            max_length = int(roa_ip['maxLength'])

        return models.IPPrefix(prefix=prefix_str, max_length=max_length)

    def _parse_aspa_payload_state(self, vaps: asn1_schema.ASPAPayloadState) -> models.ASPAPayloadState:
        """Parse ASPA payload state."""
        payload_sets = []
        for aps in vaps['aps']:
            payload_set = self._parse_aspa_payload_set(aps)
            payload_sets.append(payload_set)

        hash_value = bytes(vaps['hash'])

        return models.ASPAPayloadState(
            payload_sets=payload_sets,
            hash=hash_value
        )

    def _parse_aspa_payload_set(self, aps: asn1_schema.ASPAPayloadSet) -> models.ASPAPayloadSet:
        """Parse a single ASPA payload set."""
        customer_asn = int(aps['customerASID'])
        provider_asns = [int(asn) for asn in aps['providers']]

        return models.ASPAPayloadSet(
            customer_asn=customer_asn,
            provider_asns=provider_asns
        )

    def _parse_trust_anchor_state(self, tas: asn1_schema.TrustAnchorState) -> models.TrustAnchorState:
        """Parse trust anchor state."""
        skis = [bytes(ski) for ski in tas['skis']]
        hash_value = bytes(tas['hash'])

        return models.TrustAnchorState(
            skis=skis,
            hash=hash_value
        )

    def _parse_router_key_state(self, rks: asn1_schema.RouterKeyState) -> models.RouterKeyState:
        """Parse router key state."""
        key_sets = []
        for rkset in rks['rksets']:
            key_set = self._parse_router_key_set(rkset)
            key_sets.append(key_set)

        hash_value = bytes(rks['hash'])

        return models.RouterKeyState(
            key_sets=key_sets,
            hash=hash_value
        )

    def _parse_router_key_set(self, rkset: asn1_schema.RouterKeySet) -> models.RouterKeySet:
        """Parse a single router key set."""
        asn = int(rkset['asID'])
        router_keys = []

        for rk in rkset['routerKeys']:
            ski = bytes(rk['ski'])
            # Encode the SPKI back to DER for storage
            from pyasn1.codec.der import encoder
            spki = encoder.encode(rk['spki'])

            router_key = models.RouterKey(ski=ski, spki=spki)
            router_keys.append(router_key)

        return models.RouterKeySet(
            asn=asn,
            router_keys=router_keys
        )
