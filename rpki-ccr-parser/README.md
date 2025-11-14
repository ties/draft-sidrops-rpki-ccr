# RPKI CCR Parser

Python library for parsing RPKI Canonical Cache Representation (CCR) files as specified in draft-spaghetti-sidrops-rpki-ccr.

## Features

- Parse CCR files (DER or base64 encoded)
- Extract manifest state, ROA payloads, ASPA payloads, trust anchors, and router keys
- Full type annotations
- Command-line interface
- Comprehensive test suite validated against test vectors

## Installation

```bash
uv pip install rpki-ccr-parser
```

## Usage

```python
from rpki_ccr_parser import CCRParser

parser = CCRParser()
ccr = parser.parse_base64(base64_string)

# Access parsed data
print(ccr.manifest_state)
print(ccr.roa_payload_state)
print(ccr.aspa_payload_state)
```

## CLI

```bash
rpki-ccr parse testvector.b64 --format json
```

## Development

```bash
uv sync --all-extras
uv run pytest tests/ -v
```

## Status

- Core parsing functionality complete (37/47 tests passing)
- IP prefix parsing and hash validation being refined
