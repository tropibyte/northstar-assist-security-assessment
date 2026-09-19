"""Read back every console-created resource into evidence/state.json.

The console creates the S3 bucket, Managed KB, Gateway and Harness (that is
where the rubric screenshots come from). This script then captures the exact
configuration AWS actually produced -- IDs, ARNs, service roles, the embedding
model, and the gateway target's connectorId -- so the ML-BOM, the IAM diff and
the threat model all quote real values instead of values retyped from a
screenshot.

Resources are located by the names in config.json. Every lookup accepts an
explicit override, because the AgentCore Managed KB does not reliably surface
through ListKnowledgeBases and may have to be supplied from the console URL.

Usage:
  python 10_discover.py
  python 10_discover.py --kb-id ABCD1234 --bucket northstar-assist-kb-90210
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (client, load_config, log, role_name_from_arn, save_state,
                       load_state, write_evidence, whoami)


def _by_name(items, name, *keys):
    for item in items:
        for key in keys:
            if item.get(key) == name:
                return item
    return None


def discover_bucket(cfg, override: str | None) -> dict:
    log("discovering S3 bucket", "step")
    s3 = client("s3", cfg)
    name = override or cfg.get("bucket")
    if not name:
        candidates = [b["Name"] for b in s3.list_buckets()["Buckets"]
                      if "northstar" in b["Name"].lower()]
        if len(candidates) == 1:
            name = candidates[0]
            log(f"auto-selected bucket {name}")
        elif candidates:
            log(f"multiple candidate buckets {candidates} - pass --bucket", "warn")
            return {"error": "ambiguous", "candidates": candidates}
        else:
            log("no northstar bucket found", "warn")
            return {"error": "not_found"}

    objects, token = [], None
    while True:
        kwargs = {"Bucket": name, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        objects.extend({"key": o["Key"], "size": o["Size"]} for o in page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            break

    by_ext: dict[str, int] = {}
    for obj in objects:
        by_ext[Path(obj["key"]).suffix.lower().lstrip(".") or "none"] = \
            by_ext.get(Path(obj["key"]).suffix.lower().lstrip(".") or "none", 0) + 1

    info = {"name": name, "object_count": len(objects), "by_extension": by_ext,
            "objects": objects}
    # 30 documents is the documented expectation; a mismatch means a partial upload.
    doc_count = sum(v for k, v in by_ext.items() if k != "none")
    if doc_count != 30:
        log(f"bucket holds {doc_count} documents, expected 30", "warn")
    else:
        log(f"bucket {name}: 30 documents across {len(by_ext)} formats", "ok")
    try:
        info["public_access_block"] = s3.get_public_access_block(
            Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError:
        info["public_access_block"] = None
    try:
        info["encryption"] = s3.get_bucket_encryption(
            Bucket=name)["ServerSideEncryptionConfiguration"]
    except ClientError:
        info["encryption"] = None
    return info


def discover_kb(cfg, override: str | None) -> dict:
    log("discovering knowledge base", "step")
    agent = client("bedrock-agent", cfg)
    kb_id = override
    if not kb_id:
        try:
            summaries = agent.list_knowledge_bases(maxResults=50).get("knowledgeBaseSummaries", [])
        except ClientError as exc:
            log(f"ListKnowledgeBases failed: {exc}", "warn")
            summaries = []
        match = _by_name(summaries, cfg["kb_name"], "name")
        if match:
            kb_id = match["knowledgeBaseId"]
        elif len(summaries) == 1:
            kb_id = summaries[0]["knowledgeBaseId"]
            log(f"auto-selected the only KB present: {kb_id}")
        else:
            log("knowledge base not found via ListKnowledgeBases.", "warn")
            log("AgentCore Managed KBs may not list here - copy the KB id from the "
                "console URL and re-run with --kb-id", "warn")
            return {"error": "not_found", "listed": summaries}

    try:
        kb = agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    except ClientError as exc:
        log(f"GetKnowledgeBase({kb_id}) failed: {exc}", "warn")
        return {"error": str(exc), "knowledgeBaseId": kb_id}

    info = {
        "knowledgeBaseId": kb["knowledgeBaseId"],
        "name": kb.get("name"),
        "arn": kb.get("knowledgeBaseArn"),
        "status": kb.get("status"),
        "roleArn": kb.get("roleArn"),
        "roleName": role_name_from_arn(kb["roleArn"]) if kb.get("roleArn") else None,
        "knowledgeBaseConfiguration": kb.get("knowledgeBaseConfiguration"),
        "storageConfiguration": kb.get("storageConfiguration"),
        "data_sources": [],
    }
    log(f"KB {kb['knowledgeBaseId']} status={kb.get('status')}", "ok")

    try:
        for summary in agent.list_data_sources(
                knowledgeBaseId=kb_id, maxResults=50).get("dataSourceSummaries", []):
            ds = agent.get_data_source(knowledgeBaseId=kb_id,
                                       dataSourceId=summary["dataSourceId"])["dataSource"]
            jobs = agent.list_ingestion_jobs(
                knowledgeBaseId=kb_id, dataSourceId=summary["dataSourceId"],
                maxResults=5).get("ingestionJobSummaries", [])
            info["data_sources"].append({
                "dataSourceId": ds["dataSourceId"],
                "name": ds.get("name"),
                "status": ds.get("status"),
                "dataSourceConfiguration": ds.get("dataSourceConfiguration"),
                "vectorIngestionConfiguration": ds.get("vectorIngestionConfiguration"),
                "ingestion_jobs": jobs,
            })
            for job in jobs:
                stats = job.get("statistics", {})
                # Indexed documents are split across NEW and MODIFIED counters.
                # Reporting only the NEW count makes a complete sync look short.
                scanned = stats.get("numberOfDocumentsScanned") or 0
                indexed = ((stats.get("numberOfNewDocumentsIndexed") or 0)
                           + (stats.get("numberOfModifiedDocumentsIndexed") or 0))
                failed = stats.get("numberOfDocumentsFailed") or 0
                skipped = stats.get("numberOfDocumentsSkipped") or 0
                log(f"  ingestion {job.get('status')}: scanned={scanned} "
                    f"indexed={indexed} (new={stats.get('numberOfNewDocumentsIndexed')}, "
                    f"modified={stats.get('numberOfModifiedDocumentsIndexed')}) "
                    f"skipped={skipped} failed={failed}")
                if failed:
                    log("  documents FAILED to ingest - the rubric requires a clean sync", "warn")
                if indexed + skipped + failed < scanned:
                    log(f"  {scanned - indexed - skipped - failed} scanned document(s) "
                        f"unaccounted for - run 12_verify_index.py", "warn")
                break
    except ClientError as exc:
        log(f"data source enumeration failed: {exc}", "warn")

    return info


def discover_gateway(cfg, override: str | None) -> dict:
    log("discovering gateway", "step")
    ctl = client("bedrock-agentcore-control", cfg)
    gw_id = override
    if not gw_id:
        items = ctl.list_gateways(maxResults=50).get("items", [])
        match = _by_name(items, cfg["gateway_name"], "name")
        if not match:
            log(f"gateway {cfg['gateway_name']} not found", "warn")
            return {"error": "not_found", "listed": items}
        gw_id = match["gatewayId"]

    gw = ctl.get_gateway(gatewayIdentifier=gw_id)
    info = {
        "gatewayId": gw.get("gatewayId"),
        "gatewayArn": gw.get("gatewayArn"),
        "gatewayUrl": gw.get("gatewayUrl"),
        "name": gw.get("name"),
        "status": gw.get("status"),
        "roleArn": gw.get("roleArn"),
        "roleName": role_name_from_arn(gw["roleArn"]) if gw.get("roleArn") else None,
        "authorizerType": gw.get("authorizerType"),
        "protocolType": gw.get("protocolType"),
        "targets": [],
    }
    log(f"gateway {info['gatewayId']} status={info['status']} auth={info['authorizerType']}", "ok")

    for summary in ctl.list_gateway_targets(gatewayIdentifier=gw_id,
                                            maxResults=50).get("items", []):
        target = ctl.get_gateway_target(gatewayIdentifier=gw_id,
                                        targetId=summary["targetId"])
        target.pop("ResponseMetadata", None)
        info["targets"].append(target)
        # The connectorId cannot be listed from any API, so capture it here:
        # it is what makes a scripted rebuild of this gateway possible.
        conn = (target.get("targetConfiguration", {}).get("mcp", {})
                .get("connector", {}).get("source", {}))
        if conn:
            log(f"  target {target.get('name')} connectorId={conn.get('connectorId')} "
                f"version={conn.get('version')}", "ok")
        creds = [c.get("credentialProviderType")
                 for c in target.get("credentialProviderConfigurations", [])]
        log(f"  target {target.get('name')} status={target.get('status')} outbound={creds}")
    return info


def discover_harness(cfg, override: str | None) -> dict:
    log("discovering harness", "step")
    ctl = client("bedrock-agentcore-control", cfg)
    h_id = override
    if not h_id:
        items = ctl.list_harnesses(maxResults=50).get("harnesses", [])
        match = _by_name(items, cfg["harness_name"], "harnessName")
        if not match:
            log(f"harness {cfg['harness_name']} not found", "warn")
            return {"error": "not_found", "listed": items}
        h_id = match["harnessId"]

    harness = ctl.get_harness(harnessId=h_id)["harness"]
    tools = harness.get("tools", [])
    info = {
        "harnessId": harness.get("harnessId"),
        "harnessName": harness.get("harnessName"),
        "arn": harness.get("arn"),
        "status": harness.get("status"),
        "harnessVersion": harness.get("harnessVersion"),
        "executionRoleArn": harness.get("executionRoleArn"),
        "executionRoleName": role_name_from_arn(harness["executionRoleArn"])
                             if harness.get("executionRoleArn") else None,
        "model": harness.get("model"),
        "systemPrompt": harness.get("systemPrompt"),
        "tools": tools,
        "memory": harness.get("memory"),
        "maxIterations": harness.get("maxIterations"),
        "maxTokens": harness.get("maxTokens"),
        "timeoutSeconds": harness.get("timeoutSeconds"),
    }
    log(f"harness {info['harnessId']} status={info['status']}", "ok")
    log(f"  role {info['executionRoleName']}")
    model_cfg = (harness.get("model") or {}).get("bedrockModelConfig", {})
    log(f"  model {model_cfg.get('modelId')}")
    # Presence of guardrailConfig here is the proof the guardrail is attached.
    extra = model_cfg.get("additionalParams") or {}
    if "guardrailConfig" in extra:
        log("  guardrailConfig IS attached", "ok")
    else:
        log("  guardrailConfig not attached yet (30_guardrail.py attaches it)")
    tool_types = [t.get("type") for t in tools]
    log(f"  tools {tool_types}")
    for unexpected in set(tool_types) - {"agentcore_gateway"}:
        log(f"  tool '{unexpected}' is enabled but not required - widens agency", "warn")
    return info


def discover_guardrail(cfg) -> dict:
    log("discovering guardrail", "step")
    bedrock = client("bedrock", cfg)
    guardrails = bedrock.list_guardrails(maxResults=50).get("guardrails", [])
    match = _by_name(guardrails, cfg["guardrail_name"], "name")
    if not match:
        log("guardrail not created yet (expected before 30_guardrail.py)")
        return {"error": "not_found"}
    detail = bedrock.get_guardrail(guardrailIdentifier=match["id"])
    detail.pop("ResponseMetadata", None)
    log(f"guardrail {match['id']} status={detail.get('status')} version={detail.get('version')}", "ok")
    return detail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bucket")
    ap.add_argument("--kb-id")
    ap.add_argument("--gateway-id")
    ap.add_argument("--harness-id")
    args = ap.parse_args()

    cfg = load_config()
    ident = whoami()
    state = load_state()
    state.update({"account_id": ident["account_id"], "region": cfg["region"]})

    bucket = discover_bucket(cfg, args.bucket)
    kb = discover_kb(cfg, args.kb_id)
    gateway = discover_gateway(cfg, args.gateway_id)
    harness = discover_harness(cfg, args.harness_id)
    guardrail = discover_guardrail(cfg)

    for label, payload in (("bucket", bucket), ("knowledge_base", kb),
                           ("gateway", gateway), ("harness", harness),
                           ("guardrail", guardrail)):
        write_evidence(f"{label}.json", payload, subdir="discovery")

    state.update({
        "bucket": bucket.get("name"),
        "kb_id": kb.get("knowledgeBaseId"),
        "kb_arn": kb.get("arn"),
        "kb_role_arn": kb.get("roleArn"),
        "data_source_id": (kb.get("data_sources") or [{}])[0].get("dataSourceId"),
        "gateway_id": gateway.get("gatewayId"),
        "gateway_arn": gateway.get("gatewayArn"),
        "gateway_url": gateway.get("gatewayUrl"),
        "gateway_role_arn": gateway.get("roleArn"),
        "gateway_target_id": (gateway.get("targets") or [{}])[0].get("targetId"),
        "harness_id": harness.get("harnessId"),
        "harness_arn": harness.get("arn"),
        "harness_role_arn": harness.get("executionRoleArn"),
        # The deployed model, not what config.json wishes were deployed. The
        # IAM narrowing scopes to this, so a console-side model change cannot
        # silently produce a policy for a profile the harness never invokes.
        "harness_model_id": ((harness.get("model") or {})
                             .get("bedrockModelConfig", {}).get("modelId")),
        "guardrail_id": guardrail.get("guardrailId"),
        "guardrail_arn": guardrail.get("guardrailArn"),
    })
    save_state(state)

    missing = [k for k in ("bucket", "kb_id", "gateway_id", "harness_id") if not state.get(k)]
    if missing:
        log(f"still missing: {', '.join(missing)} - create them in the console, then re-run", "warn")
        return 2
    log("discovery complete - state.json is the source of truth from here", "ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
