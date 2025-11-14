"""Command-line interface for CCR parser."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from . import CCRParser
from . import utils


def ccr_to_dict(ccr) -> Dict[str, Any]:
    """Convert CCR object to dictionary for JSON serialization."""
    result: Dict[str, Any] = {
        'version': ccr.version,
        'hash_algorithm': ccr.hash_algorithm,
        'produced_at': ccr.produced_at.isoformat(),
    }

    if ccr.manifest_state:
        result['manifest_state'] = {
            'most_recent_update': ccr.manifest_state.most_recent_update.isoformat(),
            'hash': utils.encode_base64(ccr.manifest_state.hash),
            'instances': [
                {
                    'hash': utils.encode_base64(mi.hash),
                    'size': mi.size,
                    'aki': utils.format_ski(mi.aki),
                    'manifest_number': f"{mi.manifest_number:X}",
                    'this_update': mi.this_update.isoformat(),
                    'locations': mi.locations,
                    'subordinates': [utils.format_ski(s) for s in mi.subordinates] if mi.subordinates else None
                }
                for mi in ccr.manifest_state.instances
            ]
        }

    if ccr.roa_payload_state:
        result['roa_payload_state'] = {
            'hash': utils.encode_base64(ccr.roa_payload_state.hash),
            'payload_sets': [
                {
                    'asn': rps.asn,
                    'prefixes': [
                        {
                            'prefix': p.prefix,
                            'max_length': p.max_length
                        }
                        for p in rps.prefixes
                    ]
                }
                for rps in ccr.roa_payload_state.payload_sets
            ]
        }

    if ccr.aspa_payload_state:
        result['aspa_payload_state'] = {
            'hash': utils.encode_base64(ccr.aspa_payload_state.hash),
            'payload_sets': [
                {
                    'customer_asn': aps.customer_asn,
                    'provider_asns': aps.provider_asns
                }
                for aps in ccr.aspa_payload_state.payload_sets
            ]
        }

    if ccr.trust_anchor_state:
        result['trust_anchor_state'] = {
            'hash': utils.encode_base64(ccr.trust_anchor_state.hash),
            'skis': [utils.format_ski(ski) for ski in ccr.trust_anchor_state.skis]
        }

    if ccr.router_key_state:
        result['router_key_state'] = {
            'hash': utils.encode_base64(ccr.router_key_state.hash),
            'key_sets': [
                {
                    'asn': ks.asn,
                    'router_keys': [
                        {
                            'ski': utils.format_ski(rk.ski),
                            'spki': utils.encode_base64(rk.spki)
                        }
                        for rk in ks.router_keys
                    ]
                }
                for ks in ccr.router_key_state.key_sets
            ]
        }

    return result


def format_text_output(ccr) -> str:
    """Format CCR object as human-readable text."""
    lines = []
    lines.append(f"CCR Version: {ccr.version}")
    lines.append(f"Hash Algorithm: {ccr.hash_algorithm}")
    lines.append(f"Produced At: {ccr.produced_at.isoformat()}")
    lines.append("")

    if ccr.manifest_state:
        ms = ccr.manifest_state
        lines.append("=== MANIFEST STATE ===")
        lines.append(f"Hash: {utils.encode_base64(ms.hash)}")
        lines.append(f"Most Recent Update: {ms.most_recent_update.isoformat()}")
        lines.append(f"Instances: {len(ms.instances)}")
        lines.append("")
        for i, mi in enumerate(ms.instances, 1):
            lines.append(f"  Manifest {i}:")
            lines.append(f"    Hash: {utils.encode_base64(mi.hash)}")
            lines.append(f"    Size: {mi.size}")
            lines.append(f"    AKI: {utils.format_ski(mi.aki)}")
            lines.append(f"    Sequence Number: {mi.manifest_number:X}")
            lines.append(f"    This Update: {mi.this_update.isoformat()}")
            lines.append(f"    Locations:")
            for loc in mi.locations:
                lines.append(f"      - {loc}")
            if mi.subordinates:
                lines.append(f"    Subordinates:")
                for sub in mi.subordinates:
                    lines.append(f"      - {utils.format_ski(sub)}")
            lines.append("")

    if ccr.roa_payload_state:
        rps = ccr.roa_payload_state
        lines.append("=== ROA PAYLOAD STATE ===")
        lines.append(f"Hash: {utils.encode_base64(rps.hash)}")
        total_prefixes = sum(len(ps.prefixes) for ps in rps.payload_sets)
        lines.append(f"Total Prefixes: {total_prefixes}")
        lines.append("")
        for ps in rps.payload_sets:
            lines.append(f"  AS{ps.asn}:")
            for prefix in ps.prefixes:
                prefix_str = str(prefix)
                lines.append(f"    {prefix_str}")
        lines.append("")

    if ccr.aspa_payload_state:
        aps_state = ccr.aspa_payload_state
        lines.append("=== ASPA PAYLOAD STATE ===")
        lines.append(f"Hash: {utils.encode_base64(aps_state.hash)}")
        lines.append(f"Total Sets: {len(aps_state.payload_sets)}")
        lines.append("")
        for aps in aps_state.payload_sets:
            providers = ', '.join(f"AS{p}" for p in aps.provider_asns)
            lines.append(f"  Customer AS{aps.customer_asn} -> Providers: {providers}")
        lines.append("")

    if ccr.trust_anchor_state:
        tas = ccr.trust_anchor_state
        lines.append("=== TRUST ANCHOR STATE ===")
        lines.append(f"Hash: {utils.encode_base64(tas.hash)}")
        lines.append(f"Trust Anchor SKIs:")
        for ski in tas.skis:
            lines.append(f"  {utils.format_ski(ski)}")
        lines.append("")

    if ccr.router_key_state:
        rks = ccr.router_key_state
        lines.append("=== ROUTER KEY STATE ===")
        lines.append(f"Hash: {utils.encode_base64(rks.hash)}")
        total_keys = sum(len(ks.router_keys) for ks in rks.key_sets)
        lines.append(f"Total Keys: {total_keys}")
        lines.append("")
        for ks in rks.key_sets:
            lines.append(f"  AS{ks.asn}:")
            for rk in ks.router_keys:
                lines.append(f"    SKI: {utils.format_ski(rk.ski)}")
                lines.append(f"    SPKI: {utils.encode_base64(rk.spki)}")
        lines.append("")

    return '\n'.join(lines)


def cmd_parse(args):
    """Handle the parse command."""
    parser = CCRParser()

    # Determine if input is base64 or binary
    try:
        with open(args.input, 'r') as f:
            content = f.read()
            # Try to decode as base64
            ccr = parser.parse_base64(content)
    except (UnicodeDecodeError, ValueError):
        # Not base64, try as binary
        ccr = parser.parse_file(args.input)

    # Format output
    if args.format == 'json':
        output = json.dumps(ccr_to_dict(ccr), indent=2)
    else:
        output = format_text_output(ccr)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Output written to {args.output}")
    else:
        print(output)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Parse and display RPKI Canonical Cache Representation (CCR) files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Parse command
    parse_parser = subparsers.add_parser('parse', help='Parse a CCR file')
    parse_parser.add_argument('input', help='Input CCR file (DER or base64)')
    parse_parser.add_argument('-f', '--format', choices=['text', 'json'], default='text',
                              help='Output format (default: text)')
    parse_parser.add_argument('-o', '--output', help='Output file (default: stdout)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'parse':
        try:
            cmd_parse(args)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
