"""Verify that what is in S3 is actually in the knowledge base index.

An ingestion job reporting failed=0 does not mean every document was indexed.
Documents can be SKIPPED or IGNORED without counting as failures, so the job
looks clean while the corpus is short. That gap matters for security work in
both directions:

  * A document that is absent cannot be retrieved, so any test that depends on
    it proves nothing. SI-01 extracts a credential from
    html/api_authentication_guide.html -- if that file is not indexed, a
    "blocked" result is meaningless.
  * A document believed to be excluded but actually present is an unrecognised
    exposure.

This lists the real per-document index status and diffs it against the S3
keys, so the corpus classification describes what the agent can actually reach.

Usage:  python 12_verify_index.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (SUBMISSION, client, die, load_config, load_state, log,
                       need, write_evidence)


def s3_keys(cfg, bucket: str) -> set[str]:
    s3 = client("s3", cfg)
    keys, token = set(), None
    while True:
        kwargs = {"Bucket": bucket, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        keys.update(o["Key"] for o in page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            break
    return keys


def indexed_documents(cfg, kb_id: str, ds_id: str) -> list[dict]:
    agent = client("bedrock-agent", cfg)
    docs, token = [], None
    while True:
        kwargs = {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        try:
            page = agent.list_knowledge_base_documents(**kwargs)
        except ClientError as exc:
            die(f"ListKnowledgeBaseDocuments failed: {exc}")
        docs.extend(page.get("documentDetails", []))
        token = page.get("nextToken")
        if not token:
            break
    return docs


def doc_key(detail: dict) -> str | None:
    identifier = detail.get("identifier") or {}
    uri = (identifier.get("s3") or {}).get("uri", "")
    # s3://bucket/key -> key
    if uri.startswith("s3://"):
        return uri.split("/", 3)[3] if uri.count("/") >= 3 else None
    return None


def main() -> int:
    cfg, state = load_config(), load_state()
    need(state, "bucket", "kb_id", "data_source_id")

    log("reading ingestion statistics", "step")
    agent = client("bedrock-agent", cfg)
    jobs = agent.list_ingestion_jobs(
        knowledgeBaseId=state["kb_id"], dataSourceId=state["data_source_id"],
        maxResults=5).get("ingestionJobSummaries", [])
    stats = {}
    if jobs:
        stats = jobs[0].get("statistics", {}) or {}
        for key in ("numberOfDocumentsScanned", "numberOfMetadataDocumentsScanned",
                    "numberOfNewDocumentsIndexed", "numberOfModifiedDocumentsIndexed",
                    "numberOfMetadataDocumentsModified", "numberOfDocumentsDeleted",
                    "numberOfDocumentsFailed", "numberOfDocumentsSkipped"):
            log(f"  {key} = {stats.get(key)}")

    log("listing indexed documents", "step")
    docs = indexed_documents(cfg, state["kb_id"], state["data_source_id"])
    by_status = Counter(d.get("status") for d in docs)
    log(f"index holds {len(docs)} document record(s): {dict(by_status)}", "ok")

    indexed_keys = {k for k in (doc_key(d) for d in docs) if k}
    bucket_keys = s3_keys(cfg, state["bucket"])

    missing = sorted(bucket_keys - indexed_keys)
    extra = sorted(indexed_keys - bucket_keys)
    not_indexed_status = [d for d in docs if d.get("status") != "INDEXED"]

    if missing:
        log(f"{len(missing)} document(s) in S3 but NOT in the index:", "warn")
        for key in missing:
            log(f"  - {key}", "warn")
    else:
        log("every S3 object has an index record", "ok")

    if not_indexed_status:
        log(f"{len(not_indexed_status)} document(s) with a non-INDEXED status:", "warn")
        for detail in not_indexed_status:
            log(f"  - {doc_key(detail)}: {detail.get('status')} "
                f"{detail.get('statusReason') or ''}", "warn")

    if extra:
        log(f"{len(extra)} indexed document(s) with no S3 object (stale):", "warn")
        for key in extra:
            log(f"  - {key}", "warn")

    report = {
        "bucket": state["bucket"],
        "kb_id": state["kb_id"],
        "ingestion_statistics": stats,
        "s3_object_count": len(bucket_keys),
        "index_record_count": len(docs),
        "status_counts": dict(by_status),
        "missing_from_index": missing,
        "non_indexed_status": [
            {"key": doc_key(d), "status": d.get("status"),
             "reason": d.get("statusReason")} for d in not_indexed_status],
        "stale_in_index": extra,
    }
    write_evidence("index_verification.json", report, subdir="discovery")

    # Retrievable = objects that are BOTH present in S3 and INDEXED. Subtracting
    # every non-INDEXED record double-counts, because a record whose source
    # object has been deleted is not in bucket_keys and was never in the
    # intersection: two stale records made a healthy 30/30 corpus read 28/30.
    # Only a non-INDEXED record whose object IS still in the bucket reduces it.
    unusable_present = {doc_key(d) for d in not_indexed_status
                        if doc_key(d) in bucket_keys}
    retrievable = len((indexed_keys & bucket_keys) - unusable_present)
    log(f"documents actually retrievable by the agent: {retrievable} of {len(bucket_keys)}",
        "ok" if retrievable == len(bucket_keys) else "warn")

    # A record whose S3 object is gone is stale bookkeeping, not a corpus fault.
    blocking = [d for d in not_indexed_status if doc_key(d) in bucket_keys]
    if extra and not blocking:
        log(f"{len(extra)} stale index record(s) refer to deleted objects; they are "
            f"not retrievable and do not affect the corpus", "warn")
    return 0 if not missing and not blocking else 2


if __name__ == "__main__":
    raise SystemExit(main())
