"""Preflight checks. Read-only, zero cost, run before anything is created.

Confirms the Cloud Lab session can actually do the work before the clock is
spent on it: credentials valid, region permitted, both models reachable, the
inference profile present, and no leftover resources from a previous attempt.

Every call here is a free control-plane List/Get. Nothing is created.

Usage:  python 00_preflight.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (client, die, load_config, log, session, update_state,
                       write_evidence, whoami)

# Udacity restricts the lab account to these four regions.
ALLOWED_REGIONS = {"us-east-1", "us-east-2", "us-west-1", "us-west-2"}


def check_identity(cfg) -> dict:
    log("checking credentials", "step")
    sess = session(cfg)
    ident = whoami(sess)
    log(f"account {ident['account_id']} as {ident['arn'].rsplit('/', 1)[-1]}", "ok")
    if cfg["region"] not in ALLOWED_REGIONS:
        die(f"region {cfg['region']} is outside the Cloud Lab allow-list {sorted(ALLOWED_REGIONS)}")
    log(f"region {cfg['region']} permitted", "ok")
    return ident


def check_models(cfg) -> dict:
    """Confirm the generation and embedding models are both usable."""
    log("checking model availability", "step")
    bedrock = client("bedrock", cfg)
    result: dict = {"foundation_models": [], "inference_profile": None, "issues": []}

    try:
        models = bedrock.list_foundation_models()["modelSummaries"]
    except ClientError as exc:
        die(f"cannot list foundation models: {exc}")

    ids = {m["modelId"] for m in models}
    result["model_count"] = len(ids)

    # The harness is configured with a cross-Region inference profile ID
    # (us.anthropic....), not a bare foundation-model ID. Resolve it so the
    # IAM policy in 20_harden_iam.py can scope to the exact ARNs involved.
    model_id = cfg["model_id"]
    if model_id.startswith(("us.", "global.", "eu.", "apac.")):
        try:
            profile = bedrock.get_inference_profile(inferenceProfileIdentifier=model_id)
            result["inference_profile"] = {
                "arn": profile["inferenceProfileArn"],
                "status": profile.get("status"),
                "models": [m["modelArn"] for m in profile.get("models", [])],
            }
            log(f"inference profile {model_id} -> {len(profile.get('models', []))} regional model ARNs", "ok")
        except ClientError as exc:
            result["issues"].append(f"inference profile {model_id}: {exc}")
            log(f"inference profile {model_id} not resolvable: {exc}", "warn")
    elif model_id not in ids:
        result["issues"].append(f"model {model_id} not listed in {cfg['region']}")
        log(f"model {model_id} not listed", "warn")
    else:
        log(f"model {model_id} available", "ok")

    embed = cfg["embedding_model_id"]
    if embed in ids:
        log(f"embedding model {embed} available", "ok")
    else:
        result["issues"].append(f"embedding model {embed} not listed in {cfg['region']}")
        log(f"embedding model {embed} not listed", "warn")

    result["foundation_models"] = sorted(
        m for m in ids if "claude" in m or "titan-embed" in m or "nova" in m
    )
    return result


def check_existing(cfg) -> dict:
    """Look for leftovers from a previous attempt so we start from a known state."""
    log("checking for existing project resources", "step")
    found: dict = {}

    def safe(label, fn):
        try:
            found[label] = fn()
        except ClientError as exc:
            found[label] = f"<not queryable: {exc.response.get('Error', {}).get('Code')}>"

    safe("s3_buckets", lambda: [
        b["Name"] for b in client("s3", cfg).list_buckets()["Buckets"]
        if "northstar" in b["Name"].lower()
    ])
    safe("knowledge_bases", lambda: [
        {"id": k["knowledgeBaseId"], "name": k["name"], "status": k["status"]}
        for k in client("bedrock-agent", cfg).list_knowledge_bases(maxResults=50)
        .get("knowledgeBaseSummaries", [])
    ])
    safe("gateways", lambda: [
        {"id": g.get("gatewayId"), "name": g.get("name"), "status": g.get("status")}
        for g in client("bedrock-agentcore-control", cfg).list_gateways(maxResults=50)
        .get("items", [])
    ])
    # NB: ListHarnesses returns "harnesses"; ListGateways returns "items".
    safe("harnesses", lambda: [
        {"id": h.get("harnessId"), "name": h.get("harnessName"),
         "arn": h.get("arn"), "status": h.get("status")}
        for h in client("bedrock-agentcore-control", cfg).list_harnesses(maxResults=50)
        .get("harnesses", [])
    ])
    safe("guardrails", lambda: [
        {"id": g["id"], "name": g["name"], "status": g["status"]}
        for g in client("bedrock", cfg).list_guardrails(maxResults=50).get("guardrails", [])
    ])

    total = sum(len(v) for v in found.values() if isinstance(v, list))
    if total:
        log(f"{total} pre-existing resource(s) found - review before building", "warn")
        for label, items in found.items():
            if isinstance(items, list) and items:
                log(f"  {label}: {items}")
    else:
        log("account is clean of project resources", "ok")
    return found


def check_logging(cfg) -> dict:
    log("checking model invocation logging", "step")
    try:
        conf = client("bedrock", cfg).get_model_invocation_logging_configuration()
        logging_config = conf.get("loggingConfig") or {}
        # The call succeeds even when nothing is configured, returning an empty
        # loggingConfig. "No exception" therefore does not mean "enabled" -- a
        # destination has to actually be present for records to be delivered.
        destinations = [k for k in ("cloudWatchConfig", "s3Config") if logging_config.get(k)]
        if destinations:
            log(f"model invocation logging is ON -> {', '.join(destinations)}", "ok")
            return {"enabled": True, "destinations": destinations, "config": logging_config}
        log("model invocation logging is OFF (empty configuration returned) - "
            "60_monitoring.py --enable-logging turns it on")
        return {"enabled": False, "destinations": [], "config": logging_config}
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            log("model invocation logging is OFF (expected - 60_monitoring.py turns it on)")
            return {"enabled": False}
        log(f"could not read logging config: {exc}", "warn")
        return {"enabled": None, "error": str(exc)}


def main() -> int:
    cfg = load_config()
    log(f"preflight for region {cfg['region']}", "step")

    ident = check_identity(cfg)
    models = check_models(cfg)
    existing = check_existing(cfg)
    logging_state = check_logging(cfg)

    report = {
        "identity": ident,
        "region": cfg["region"],
        "config": cfg,
        "models": models,
        "existing_resources": existing,
        "model_invocation_logging": logging_state,
    }
    write_evidence("preflight.json", report)
    update_state(account_id=ident["account_id"], region=cfg["region"],
                 caller_arn=ident["arn"])

    if models["issues"]:
        log("preflight completed WITH ISSUES:", "warn")
        for issue in models["issues"]:
            log(f"  - {issue}", "warn")
        log("a missing model is usually a region problem - check the console model list", "warn")
        return 2

    log("preflight clean - safe to build", "ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
