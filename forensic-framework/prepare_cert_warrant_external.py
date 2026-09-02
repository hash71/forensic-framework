#!/usr/bin/env python3
"""Prepare compact, provenance-hashed CERT r4.2 external warrant cases."""

from __future__ import annotations

import json

from app.ingestion.warrant_external import prepare_cert_warrant_cases


def main() -> int:
    print(json.dumps(prepare_cert_warrant_cases(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
