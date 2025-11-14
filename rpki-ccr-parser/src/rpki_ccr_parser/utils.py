"""Utility functions for CCR parsing."""

import base64
import hashlib
import ipaddress
from datetime import datetime
from typing import Union


def decode_base64(b64_string: str) -> bytes:
    """
    Decode a base64 string to bytes.

    Args:
        b64_string: Base64-encoded string (may contain whitespace)

    Returns:
        Decoded bytes
    """
    # Remove whitespace
    b64_clean = ''.join(b64_string.split())
    return base64.b64decode(b64_clean)


def encode_base64(data: bytes) -> str:
    """
    Encode bytes to base64 string.

    Args:
        data: Bytes to encode

    Returns:
        Base64-encoded string
    """
    return base64.b64encode(data).decode('ascii')


def compute_hash(data: bytes, algorithm: str = 'sha256') -> bytes:
    """
    Compute hash of data using specified algorithm.

    Args:
        data: Data to hash
        algorithm: Hash algorithm ('sha256', 'sha384', 'sha512')

    Returns:
        Hash digest bytes
    """
    algo_map = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        '2.16.840.1.101.3.4.2.1': hashlib.sha256,  # OID for SHA-256
        '2.16.840.1.101.3.4.2.2': hashlib.sha384,  # OID for SHA-384
        '2.16.840.1.101.3.4.2.3': hashlib.sha512,  # OID for SHA-512
    }

    hasher = algo_map.get(algorithm.lower())
    if not hasher:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    return hasher(data).digest()


def parse_generalized_time(gt_string: Union[str, bytes]) -> datetime:
    """
    Parse ASN.1 GeneralizedTime to datetime.

    Args:
        gt_string: GeneralizedTime string (e.g., '20251012223705Z')

    Returns:
        datetime object
    """
    if isinstance(gt_string, bytes):
        gt_string = gt_string.decode('ascii')

    # Remove 'Z' suffix if present
    if gt_string.endswith('Z'):
        gt_string = gt_string[:-1]

    # Parse various formats
    formats = [
        '%Y%m%d%H%M%S',
        '%Y%m%d%H%M%S.%f',
    ]

    for fmt in formats:
        try:
            return datetime.strptime(gt_string, fmt)
        except ValueError:
            continue

    raise ValueError(f"Cannot parse GeneralizedTime: {gt_string}")


def format_asn(asn: int) -> str:
    """
    Format an AS number.

    Args:
        asn: AS number

    Returns:
        Formatted string (e.g., 'AS65000')
    """
    return f"AS{asn}"


def bits_to_ip_prefix(bits: bytes, bit_length: int, afi: int) -> str:
    """
    Convert bit string to IP prefix.

    Args:
        bits: Bit string bytes
        bit_length: Number of bits in the prefix
        afi: Address Family Identifier (1 for IPv4, 2 for IPv6)

    Returns:
        IP prefix string (e.g., '192.0.2.0/24')
    """
    if afi == 1:  # IPv4
        # Pad to 4 bytes
        padded = bits + b'\x00' * (4 - len(bits))
        addr = ipaddress.IPv4Address(padded[:4])
        return f"{addr}/{bit_length}"
    elif afi == 2:  # IPv6
        # Pad to 16 bytes
        padded = bits + b'\x00' * (16 - len(bits))
        addr = ipaddress.IPv6Address(padded[:16])
        return f"{addr}/{bit_length}"
    else:
        raise ValueError(f"Unsupported AFI: {afi}")


def parse_afi_from_octets(octets: bytes) -> int:
    """
    Parse AFI from octet string.

    Args:
        octets: AFI octets (2 bytes for IPv4/IPv6)

    Returns:
        AFI value (1 for IPv4, 2 for IPv6)
    """
    if len(octets) == 2:
        afi = int.from_bytes(octets, byteorder='big')
        return afi
    raise ValueError(f"Invalid AFI octets length: {len(octets)}")


def format_ski(ski: bytes) -> str:
    """
    Format Subject Key Identifier as hex string.

    Args:
        ski: SKI bytes

    Returns:
        Uppercase hex string
    """
    return ski.hex().upper()


def parse_access_location(location: bytes) -> str:
    """
    Parse access location from GeneralName.

    Args:
        location: DER-encoded GeneralName

    Returns:
        Location string (typically rsync or https URI)
    """
    # GeneralName is a CHOICE, uniformResourceIdentifier is [6] IA5String
    if location and location[0] == 0x86:  # Context tag 6
        # Skip tag and length
        if location[1] < 128:
            return location[2:].decode('ascii')
        else:
            # Long form length
            len_octets = location[1] & 0x7f
            return location[2 + len_octets:].decode('ascii')
    return location.decode('ascii', errors='replace')


def oid_to_string(oid: tuple) -> str:
    """
    Convert OID tuple to string.

    Args:
        oid: OID tuple (e.g., (2, 16, 840, 1, 101, 3, 4, 2, 1))

    Returns:
        OID string (e.g., '2.16.840.1.101.3.4.2.1')
    """
    return '.'.join(str(x) for x in oid)
