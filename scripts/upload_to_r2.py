#!/usr/bin/env python3
"""
Upload a file to Cloudflare R2 (S3-compatible API).

Supports two auth modes:
  1. R2 Access Key ID + Secret Key (S3 signature)
  2. Cloudflare API Token (Bearer token)

Usage:
    python3 upload_to_r2.py --file config.yaml --bucket config --key config.yaml
"""

from __future__ import annotations

import argparse
import os
import sys

import requests


R2_ACCOUNT_ID = "6ebc3ef97b0aca55c0f4660685627750"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--file", required=True, help="Local file to upload")
    p.add_argument("--bucket", default="config", help="R2 bucket name")
    p.add_argument("--key", default="config.yaml", help="Object key")
    p.add_argument("--content-type", default="application/yaml")
    p.add_argument("--account-id", default=os.getenv("R2_ACCOUNT_ID", R2_ACCOUNT_ID))
    p.add_argument("--access-key", default=os.getenv("R2_ACCESS_KEY_ID"))
    p.add_argument("--secret-key", default=os.getenv("R2_SECRET_ACCESS_KEY"))
    p.add_argument("--api-token", default=os.getenv("CF_API_TOKEN"))
    return p.parse_args()


def upload_via_api_token(file_path: str, bucket: str, key: str,
                         account_id: str, token: str, content_type: str) -> bool:
    """Upload using Cloudflare API Token (Bearer auth)."""
    size = os.path.getsize(file_path)
    print(f"[INFO] Uploading {file_path} ({size:,} bytes)")
    print(f"[INFO] Target: {account_id}/r2/{bucket}/{key}")

    url = (
        f"https://api.cloudflare.com/client/v4/accounts/"
        f"{account_id}/r2/buckets/{bucket}/objects/{key}"
    )

    with open(file_path, "rb") as f:
        resp = requests.put(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": content_type,
            },
            data=f,
            timeout=60,
        )

    if resp.status_code in (200, 201):
        print(f"[OK] Uploaded: https://{account_id}.r2.cloudflarestorage.com/{bucket}/{key}")
        return True

    print(f"[WARN] API returned {resp.status_code}: {resp.text[:300]}")
    return False


def upload_via_s3(file_path: str, bucket: str, key: str,
                  account_id: str, access_key: str, secret_key: str,
                  content_type: str) -> bool:
    """Upload using R2 S3-compatible API with AWS SigV4."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        print("[WARN] boto3 not installed")
        return False

    endpoint = f"https://{account_id}.r2.cloudflarestorage.com"
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )

    size = os.path.getsize(file_path)
    print(f"[INFO] S3 upload: {file_path} ({size:,} bytes) -> s3://{bucket}/{key}")

    s3.upload_file(file_path, bucket, key, ExtraArgs={"ContentType": content_type})
    print(f"[OK] {endpoint}/{bucket}/{key}")
    return True


def main() -> int:
    args = parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
        return 1

    # Try S3 mode first (if access key provided)
    if args.access_key and args.secret_key:
        if upload_via_s3(args.file, args.bucket, args.key,
                         args.account_id, args.access_key, args.secret_key,
                         args.content_type):
            return 0

    # Try API token mode
    if args.api_token:
        if upload_via_api_token(args.file, args.bucket, args.key,
                                args.account_id, args.api_token,
                                args.content_type):
            return 0

    print("[ERROR] No valid credentials. Set R2_ACCESS_KEY_ID + R2_SECRET_ACCESS_KEY or CF_API_TOKEN",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
