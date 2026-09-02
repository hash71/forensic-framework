#!/usr/bin/env python3
"""Create a blinded adjudication UI from two completed independent reviews."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_human import export_adjudication_package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("annotator_1_csv", type=Path)
    parser.add_argument("annotator_2_csv", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    manifest = export_adjudication_package(
        args.package_dir,
        args.annotator_1_csv,
        args.annotator_2_csv,
        args.output_dir,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
