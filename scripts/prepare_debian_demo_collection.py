#!/usr/bin/env python3
"""Prepare a fresh, system-only collection request inside an owned Debian VM.

This writes local scope documents; it never reads evidence or starts collection.
"""

import argparse
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


def timestamp(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-name", required=True, help="Name of your separate Debian demo VM")
    parser.add_argument("--vm-uuid", required=True, type=uuid.UUID, help="libvirt UUID shown by virsh on the host")
    parser.add_argument("--output-dir", required=True, type=Path, help="New private directory in the guest")
    args = parser.parse_args()
    if not args.vm_name.strip() or args.vm_name == "jocky-v5-debian-13-7":
        parser.error("use the separate desktop VM name, not the pinned evidence VM")
    if args.output_dir.exists():
        parser.error("output directory must be new; old requests are never reused")
    product_uuid = str(args.vm_uuid)

    template_dir = Path(__file__).resolve().parents[1] / "fixtures/valid/collection"
    names = ("endpoint-designation", "authorisation", "policy", "request")
    documents = {name: json.loads((template_dir / f"{name}.json").read_text()) for name in names}
    old_ids = {
        "10000000-0000-4000-8000-000000000001": str(uuid.uuid4()),  # designation
        "10000000-0000-4000-8000-000000000002": str(uuid.uuid4()),  # endpoint
        "10000000-0000-4000-8000-000000000003": str(uuid.uuid4()),  # operator
        "10000000-0000-4000-8000-000000000004": str(uuid.uuid4()),  # authorisation
        "10000000-0000-4000-8000-000000000005": str(uuid.uuid4()),  # case
        "10000000-0000-4000-8000-000000000006": str(uuid.uuid4()),  # policy
        "10000000-0000-4000-8000-000000000007": str(uuid.uuid4()),  # collection
        "10000000-0000-4000-8000-000000000008": str(uuid.uuid4()),  # source
    }
    now = datetime.now(timezone.utc)
    replacements = {
        **old_ids,
        "2020-01-01T00:00:00Z": timestamp(now - timedelta(minutes=1)),
        "2020-01-01T01:00:00Z": timestamp(now + timedelta(hours=2)),
        "synthetic-test-only": args.vm_name,
        "synthetic-test-only-not-an-endpoint-designation": f"vm-product-uuid:{product_uuid}",
    }
    # Replace exact JSON string values only. Leave limits and allowed source types intact.
    def replace(value):
        if isinstance(value, str):
            return replacements.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    os.mkdir(args.output_dir, 0o700)
    for name, document in documents.items():
        path = args.output_dir / f"{name}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(replace(document), output, indent=2)
            output.write("\n")
    print(f"Wrote four private system-only inputs in {args.output_dir}")
    print(f"VM product UUID: {product_uuid}")
    print(f"Valid until: {timestamp(now + timedelta(hours=2))}")
    print("Collection has not started. Review the four files before collect.")


if __name__ == "__main__":
    main()
