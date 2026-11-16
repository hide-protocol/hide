#!/usr/bin/env python3
"""Drives the Python SDK for the cross-surface interop matrix. Two commands:

    python python_adapter.py encrypt <public-key> <plaintext> <out-container>
    python python_adapter.py decrypt <secret-key> <container> <out-plaintext>

The SDK is imported from this checkout rather than from site-packages, so the
matrix tests the sources in the tree. The native core is found through
``HIDE_LIBRARY`` + ``HIDE_ALLOW_LIBRARY_OVERRIDE``, which the harness exports.
"""

from __future__ import annotations

import sys
from pathlib import Path

# conformance/cross-surface/adapters/ -> repository root
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sdk" / "python" / "src"))

import hide_protocol as hide  # noqa: E402  (the path above must come first)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: python_adapter.py encrypt|decrypt <key> <input> <output>",
            file=sys.stderr,
        )
        return 2
    command, key_path, input_path, output_path = argv
    key = Path(key_path).read_bytes()
    data = Path(input_path).read_bytes()

    if command == "encrypt":
        Path(output_path).write_bytes(hide.encrypt(data, [key], filename="python.txt"))
    elif command == "decrypt":
        # A protected key file would need a passphrase, which a cross-surface
        # vector never carries; the matrix uses raw seeds.
        with hide.SecretKey.load(key) as secret:
            Path(output_path).write_bytes(hide.decrypt(data, secret).data)
    else:
        print(f"unknown command: {command}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
