"""Find out which foundation models this account can actually invoke.

ListFoundationModels reports what exists in the region, not what the account
is entitled to use. A model can be listed, have a resolvable inference profile,
and still fail at invoke time with:

    AccessDeniedException ... not authorized to perform the required AWS
    Marketplace actions (aws-marketplace:ViewSubscriptions, Subscribe)

which means no Marketplace agreement exists for it. GetFoundationModelAvailability
reports the real position: agreement, entitlement, authorization and region.

This probes every tool-capable candidate, and with --fix attempts to accept the
agreement for the preferred model. In a restricted lab account that attempt may
itself be denied, in which case the answer is to switch to a model the account
already holds -- Amazon first-party models need no Marketplace agreement, which
is why Nova 2 Lite is the reliable fallback.

Usage:
  python 02_model_access.py                 # probe and recommend
  python 02_model_access.py --fix           # try to accept the agreement
  python 02_model_access.py --set <modelId> # write the choice into config.json
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (client, load_config, log, save_config, write_evidence)

# Ordered by preference: tool-call capable, cheapest first, and the brief's
# explicit warning that Nova Lite v1 / Nova Pro v1 fail on ToolUse is honoured
# by keeping them out of the recommendation list entirely.
CANDIDATES = [
    ("anthropic.claude-haiku-4-5-20251001-v1:0", "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
    ("amazon.nova-2-lite-v1:0", "us.amazon.nova-2-lite-v1:0"),
    ("anthropic.claude-sonnet-4-5-20250929-v1:0", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
    ("anthropic.claude-sonnet-4-6", "global.anthropic.claude-sonnet-4-6"),
]


def probe(bedrock, model_id: str) -> dict:
    try:
        r = bedrock.get_foundation_model_availability(modelId=model_id)
    except ClientError as exc:
        return {"modelId": model_id, "error": exc.response.get("Error", {}).get("Code"),
                "message": exc.response.get("Error", {}).get("Message")}
    agreement = r.get("agreementAvailability") or {}
    return {
        "modelId": model_id,
        "authorizationStatus": r.get("authorizationStatus"),
        "entitlementAvailability": r.get("entitlementAvailability"),
        "regionAvailability": r.get("regionAvailability"),
        "agreementStatus": agreement.get("status"),
        "agreementErrorMessage": agreement.get("errorMessage"),
    }


def usable(result: dict) -> bool:
    """All four signals must line up, not just the first three.

    authorizationStatus/entitlement/region can all read AVAILABLE while
    agreementAvailability.status is NOT_AVAILABLE, and that last field is the
    one that decides whether invocation succeeds: no Marketplace agreement
    means ConverseStream fails with an aws-marketplace:Subscribe denial.
    AWS first-party models (Amazon Nova) need no agreement and report
    AVAILABLE, which is what makes them the reliable fallback in a restricted
    lab account.
    """
    return (result.get("authorizationStatus") == "AUTHORIZED"
            and result.get("entitlementAvailability") == "AVAILABLE"
            and result.get("regionAvailability") == "AVAILABLE"
            and result.get("agreementStatus") == "AVAILABLE")


def resolve_profile(bedrock, base_model_id: str, fallback: str) -> str:
    """Find the real cross-Region inference profile fronting this model.

    Profile IDs are not reliably the base ID with a 'us.' prefix, so match on
    the model ARNs the profile actually routes to.
    """
    try:
        profiles = bedrock.list_inference_profiles(maxResults=100).get(
            "inferenceProfileSummaries", [])
    except ClientError:
        return fallback
    for profile in profiles:
        for model in profile.get("models", []):
            if model.get("modelArn", "").endswith(f"/{base_model_id}"):
                return profile.get("inferenceProfileId") or fallback
    return fallback


def try_agreement(bedrock, model_id: str) -> bool:
    """Accept the Marketplace offer, if this principal is allowed to."""
    try:
        offers = bedrock.list_foundation_model_agreement_offers(
            modelId=model_id).get("offers", [])
    except ClientError as exc:
        log(f"  cannot list offers: {exc.response.get('Error', {}).get('Code')}", "warn")
        return False
    if not offers:
        log("  no offers returned", "warn")
        return False
    token = offers[0].get("offerToken")
    try:
        bedrock.create_foundation_model_agreement(modelId=model_id, offerToken=token)
        log(f"  agreement accepted for {model_id}", "ok")
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        log(f"  agreement rejected ({code}) - this account cannot subscribe", "warn")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fix", action="store_true",
                    help="attempt to accept the Marketplace agreement for unusable models")
    ap.add_argument("--set", dest="set_model",
                    help="write this inference profile id into config.json as model_id")
    args = ap.parse_args()

    cfg = load_config()

    if args.set_model:
        cfg["model_id"] = args.set_model
        save_config(cfg)
        log(f"config.json model_id = {args.set_model}", "ok")
        log("re-run 00_preflight.py so the inference profile ARNs are recaptured "
            "for the IAM narrowing", "warn")
        return 0

    bedrock = client("bedrock", cfg)
    results = []
    log("probing model access (listing a model does not mean you can invoke it)", "step")
    for base_id, profile_fallback in CANDIDATES:
        result = probe(bedrock, base_id)
        profile_id = resolve_profile(bedrock, base_id, profile_fallback)
        result["inference_profile"] = profile_id
        results.append(result)
        if result.get("error"):
            log(f"  {base_id}: {result['error']}", "warn")
            continue
        mark = "ok" if usable(result) else "warn"
        log(f"  {base_id}: auth={result['authorizationStatus']} "
            f"entitlement={result['entitlementAvailability']} "
            f"region={result['regionAvailability']} "
            f"agreement={result['agreementStatus']}", mark)

        if args.fix and not usable(result):
            log(f"  attempting agreement for {base_id}", "step")
            if try_agreement(bedrock, base_id):
                refreshed = probe(bedrock, base_id)
                refreshed["inference_profile"] = profile_id
                results[-1] = refreshed
                log(f"  now auth={refreshed['authorizationStatus']} "
                    f"entitlement={refreshed['entitlementAvailability']}",
                    "ok" if usable(refreshed) else "warn")

    write_evidence("model_access.json", {"region": cfg["region"], "results": results})

    good = [r for r in results if usable(r)]
    if not good:
        log("no candidate model is currently invokable in this account", "err")
        log("options: (1) Bedrock console > Model access > enable the model, "
            "(2) re-run with --fix, (3) ask Udacity support to enable it", "warn")
        return 2

    best = good[0]
    log(f"usable models: {[r['modelId'] for r in good]}", "ok")
    log(f"recommended: {best['inference_profile']}", "ok")
    if best["inference_profile"] != cfg["model_id"]:
        log(f"config.json currently says {cfg['model_id']} - to switch, run:", "warn")
        log(f"  python 02_model_access.py --set {best['inference_profile']}", "warn")
        log("  then re-run 00_preflight.py, and update the harness model in the console", "warn")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
