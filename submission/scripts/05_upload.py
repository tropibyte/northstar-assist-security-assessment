"""Create the document bucket with secure defaults and upload the corpus.

The console's Add-folder upload works, but doing it here buys three things the
console default does not: public access explicitly blocked, default encryption
on, and a verified object count so a partial upload is caught immediately
rather than surfacing later as a short knowledge base.

The bucket is the knowledge base's source of truth. Anything readable here is
reachable by the agent, which is why the corpus classification in
docs/corpus-classification.md is scoped to exactly this upload.

Usage:
  python 05_upload.py            # create bucket, upload, verify
  python 05_upload.py --verify   # count objects only, change nothing
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (REPO, client, die, load_config, log, update_state,
                       write_evidence)

CORPUS = REPO / "project" / "northstar-knowledge-base"
PREFIX = "northstar-knowledge-base"
CONTENT_TYPES = {
    ".csv": "text/csv", ".txt": "text/plain", ".html": "text/html",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def ensure_bucket(s3, bucket: str, region: str) -> None:
    try:
        s3.head_bucket(Bucket=bucket)
        log(f"bucket {bucket} already exists")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in {"404", "NoSuchBucket", "403"}:
            raise
        if code == "403":
            die(f"bucket name {bucket} is taken by another account - pick a different "
                f"suffix in config.json")
        kwargs = {"Bucket": bucket}
        # us-east-1 rejects an explicit LocationConstraint.
        if region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**kwargs)
        log(f"created bucket {bucket}", "ok")

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        })
    log("public access blocked on all four settings", "ok")

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                       "BucketKeyEnabled": True}]})
    log("default encryption enabled (SSE-S3)", "ok")


def upload(s3, bucket: str) -> list[dict]:
    if not CORPUS.is_dir():
        die(f"corpus not found at {CORPUS}")
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
    log(f"uploading {len(files)} documents", "step")

    uploaded = []
    for path in files:
        key = f"{PREFIX}/{path.relative_to(CORPUS).as_posix()}"
        s3.upload_file(str(path), bucket, key, ExtraArgs={
            "ContentType": CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")})
        uploaded.append({"key": key, "bytes": path.stat().st_size})
    log(f"uploaded {len(uploaded)} objects", "ok")
    return uploaded


def verify(s3, bucket: str) -> dict:
    objects, token = [], None
    while True:
        kwargs = {"Bucket": bucket, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        objects.extend({"key": o["Key"], "size": o["Size"]} for o in page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            break

    by_ext: dict[str, int] = {}
    for obj in objects:
        ext = Path(obj["key"]).suffix.lower().lstrip(".") or "none"
        by_ext[ext] = by_ext.get(ext, 0) + 1

    log(f"bucket holds {len(objects)} objects: {by_ext}",
        "ok" if len(objects) == 30 else "warn")
    if len(objects) != 30:
        log("expected exactly 30 documents - check for a partial upload", "warn")
    return {"count": len(objects), "by_extension": by_ext, "objects": objects}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()

    cfg = load_config()
    bucket = cfg.get("bucket", "")
    if not bucket or "REPLACE" in bucket:
        die("set 'bucket' in submission/config.json first")

    s3 = client("s3", cfg)
    if not args.verify:
        ensure_bucket(s3, bucket, cfg["region"])
        upload(s3, bucket)

    report = verify(s3, bucket)
    report["bucket"] = bucket
    write_evidence("s3_upload.json", report, subdir="discovery")
    update_state(bucket=bucket)
    log(f"s3://{bucket}/{PREFIX}/ is ready - use this URI as the KB data source", "ok")
    log(f"  S3 URI for the console: s3://{bucket}/", "ok")
    return 0 if report["count"] == 30 else 2


if __name__ == "__main__":
    raise SystemExit(main())
