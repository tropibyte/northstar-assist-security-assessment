"""Create the Bedrock Guardrail and attach it to the harness (Task 5).

Three things have to happen, and the second is the one that silently breaks
every request if skipped: the console-generated harness execution role does
NOT include bedrock:ApplyGuardrail, so attaching a guardrail without adding
that permission makes every invocation fail with AccessDeniedException.

  1. CreateGuardrail from guardrail/guardrail.json, then CreateGuardrailVersion
  2. Add an inline policy granting ApplyGuardrail on THIS guardrail only
  3. UpdateHarness so model.bedrockModelConfig.additionalParams carries
     guardrailConfig

Attachment is a read-modify-write: GetHarness, merge, write every updatable
field back. UpdateHarness accepts partial input, and relying on unspecified
merge semantics risks clearing the gateway tool, which would quietly turn the
agent into a non-RAG chatbot that still looks like it works.

--detach removes the guardrail without deleting it, so the test suite can be
run against the same harness with controls off and then on. That baseline
comparison is what turns "the guardrail blocked it" into a measured delta.

Usage:
  python 30_guardrail.py --create            # create + version only
  python 30_guardrail.py --attach            # grant permission + attach
  python 30_guardrail.py --create --attach
  python 30_guardrail.py --detach            # remove from harness, keep guardrail
  python 30_guardrail.py --status
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (SUBMISSION, client, die, load_config, load_state, log,
                       need, role_name_from_arn, update_state, write_evidence)

GUARDRAIL_JSON = SUBMISSION / "guardrail" / "guardrail.json"
APPLY_POLICY_NAME = "NorthstarAssistApplyGuardrail"

# Fields GetHarness returns that UpdateHarness will also accept. Computed
# against the live model so a future API addition does not silently drop config.
def updatable_fields(ctl) -> set[str]:
    members = set(ctl.meta.service_model.operation_model("UpdateHarness").input_shape.members)
    return members - {"harnessId", "clientToken"}


def prune_to_shape(value, shape):
    """Drop members the target shape does not accept, at every nesting level.

    GetHarness and UpdateHarness share top-level field names but not their
    nested contents: the read returns environment.agentCoreRuntimeEnvironment
    with agentRuntimeArn/Name/Id, and memory as {"disabled": ...}, none of
    which UpdateHarness accepts. Filtering only the top level therefore passes
    the read straight back into a ParamValidationError, so the filter has to
    recurse.

    Document-typed members (additionalParams, where guardrailConfig lives) are
    arbitrary JSON and must pass through untouched.
    """
    kind = shape.type_name
    if kind == "structure":
        if getattr(shape, "is_document_type", False) or not isinstance(value, dict):
            return value
        pruned = {}
        for key, item in value.items():
            member = shape.members.get(key)
            if member is None:
                continue
            result = prune_to_shape(item, member)
            # An object whose every member was rejected carries no information
            # and may be invalid on its own; drop it rather than send {}.
            if isinstance(item, dict) and item and isinstance(result, dict) and not result:
                continue
            pruned[key] = result
        return pruned
    if kind == "list":
        return [prune_to_shape(i, shape.member) for i in value] if isinstance(value, list) else value
    if kind == "map":
        return ({k: prune_to_shape(v, shape.value) for k, v in value.items()}
                if isinstance(value, dict) else value)
    return value


def strip_notes(value):
    """Remove underscore-prefixed annotation keys at every level.

    guardrail.json carries `_note` / `_v2_note` fields recording why each
    control is set the way it is -- the file is a deliverable as well as an API
    payload. Those keys are not valid API members, and stripping only the top
    level leaves nested ones to be rejected.
    """
    if isinstance(value, dict):
        return {k: strip_notes(v) for k, v in value.items() if not k.startswith("_")}
    if isinstance(value, list):
        return [strip_notes(v) for v in value]
    return value


def downgrade_to_classic(spec: dict) -> dict:
    """Strip STANDARD-tier settings so the guardrail can be created anyway.

    STANDARD tier gives better multilingual and prompt-attack detection but
    requires guardrail cross-Region inference. Where that profile is not
    available (restricted lab accounts), CLASSIC still provides every filter
    this project configures -- the difference is detection quality, not
    coverage. The applied tier is recorded so the write-up states which one
    the tested results actually reflect.
    """
    downgraded = copy.deepcopy(spec)
    downgraded.pop("crossRegionConfig", None)
    for policy in ("topicPolicyConfig", "contentPolicyConfig"):
        if policy in downgraded:
            downgraded[policy].pop("tierConfig", None)
    return downgraded


def _tier_error(exc: ClientError) -> bool:
    message = str(exc).lower()
    return "tier" in message or "cross-region" in message


def create_guardrail(cfg, state) -> dict:
    bedrock = client("bedrock", cfg)
    spec = strip_notes(json.loads(GUARDRAIL_JSON.read_text(encoding="utf-8")))
    tier = "STANDARD"

    existing = next((g for g in bedrock.list_guardrails(maxResults=50).get("guardrails", [])
                     if g["name"] == spec["name"]), None)

    def send(payload: dict):
        if existing:
            body = dict(payload)
            body.pop("tags", None)  # UpdateGuardrail does not take tags
            bedrock.update_guardrail(guardrailIdentifier=existing["id"], **body)
            return existing["id"], existing["arn"]
        created = bedrock.create_guardrail(**payload)
        return created["guardrailId"], created["guardrailArn"]

    verb = "updating" if existing else "creating"
    log(f"{verb} guardrail {spec['name']} (tier {tier})", "step")
    try:
        guardrail_id, guardrail_arn = send(spec)
    except ClientError as exc:
        if not _tier_error(exc):
            raise
        log(f"STANDARD tier unavailable: {exc.response.get('Error', {}).get('Message')}", "warn")
        log("retrying with CLASSIC tier - all configured filters still apply, "
            "detection quality is lower", "warn")
        tier = "CLASSIC"
        guardrail_id, guardrail_arn = send(downgrade_to_classic(spec))
    log(f"{'updated' if existing else 'created'} {guardrail_id} at {tier} tier", "ok")

    # A guardrail must reach READY before a version can be cut.
    for _ in range(30):
        detail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        if detail["status"] == "READY":
            break
        if detail["status"] == "FAILED":
            die(f"guardrail FAILED: {detail.get('statusReasons')} "
                f"{detail.get('failureRecommendations')}")
        log(f"  status {detail['status']} - waiting")
        time.sleep(5)
    else:
        die("guardrail did not reach READY in time")

    version = bedrock.create_guardrail_version(
        guardrailIdentifier=guardrail_id,
        description="Northstar Assist launch-readiness validation")["version"]
    log(f"guardrail version {version} created", "ok")

    detail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)
    detail.pop("ResponseMetadata", None)
    write_evidence("guardrail_created.json", detail, subdir="discovery")

    counts = {
        "topics": len(detail.get("topicPolicy", {}).get("topics", [])),
        "content_filters": len(detail.get("contentPolicy", {}).get("filters", [])),
        "pii_entities": len(detail.get("sensitiveInformationPolicy", {}).get("piiEntities", [])),
        "regexes": len(detail.get("sensitiveInformationPolicy", {}).get("regexes", [])),
        "grounding_filters": len(detail.get("contextualGroundingPolicy", {}).get("filters", [])),
    }
    log(f"applied policies: {counts}", "ok")

    update_state(guardrail_id=guardrail_id, guardrail_arn=guardrail_arn,
                 guardrail_version=version, guardrail_tier=tier)
    return {"id": guardrail_id, "arn": guardrail_arn, "version": version,
            "tier": tier, "counts": counts}


def inference_regions(state: dict) -> list[str]:
    """Regions the model's inference profile can route to.

    Read from the preflight capture of the live profile rather than assumed,
    falling back to the home region plus the standard US cross-Region set if
    that capture is missing.
    """
    path = SUBMISSION / "evidence" / "preflight.json"
    regions: list[str] = []
    try:
        profile = (json.loads(path.read_text(encoding="utf-8"))
                   .get("models", {}).get("inference_profile") or {})
        for arn in profile.get("models", []):
            parts = arn.split(":")
            if len(parts) > 3 and parts[3] and parts[3] not in regions:
                regions.append(parts[3])
    except (json.JSONDecodeError, OSError, KeyError):
        pass
    if not regions:
        regions = ["us-east-1", "us-east-2", "us-west-2"]
    if state.get("region") and state["region"] not in regions:
        regions.append(state["region"])
    return regions


def grant_apply_permission(cfg, state) -> None:
    """Without this the harness fails every request once a guardrail is attached."""
    need(state, "harness_role_arn", "guardrail_arn")
    role_name = role_name_from_arn(state["harness_role_arn"])

    resources = [state["guardrail_arn"]]
    # A STANDARD-tier guardrail runs through cross-Region inference, and the
    # authorisation check then covers TWO resources: the guardrail and the
    # guardrail PROFILE that fronts it. Granting only the guardrail ARN -- which
    # is what the project brief's sample policy does -- fails with
    # "not authorized ... on resource: .../guardrail-profile/us.guardrail.v1:0".
    #
    # Worse, the profile ARN is REGIONAL and follows wherever the model call is
    # routed, so granting only the home region works until traffic lands
    # elsewhere and then fails intermittently. The regions are taken from the
    # model's own inference profile: the guardrail is applied where inference
    # runs, so those are exactly the regions needed -- no wildcard required.
    if state.get("guardrail_tier") == "STANDARD":
        spec = json.loads(GUARDRAIL_JSON.read_text(encoding="utf-8"))
        profile = (spec.get("crossRegionConfig") or {}).get("guardrailProfileIdentifier")
        if profile:
            for region in inference_regions(state):
                resources.append(f"arn:aws:bedrock:{region}:{state['account_id']}:"
                                 f"guardrail-profile/{profile}")
            log(f"  STANDARD tier: granting guardrail profile {profile} in "
                f"{len(resources) - 1} region(s)")

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ApplyNorthstarGuardrail",
            "Effect": "Allow",
            "Action": "bedrock:ApplyGuardrail",
            # Still enumerated, not wildcarded: ApplyGuardrail on * would let
            # the role apply any guardrail in the account, including a
            # permissive one it could create for itself.
            "Resource": resources,
        }],
    }
    client("iam", cfg).put_role_policy(
        RoleName=role_name, PolicyName=APPLY_POLICY_NAME,
        PolicyDocument=json.dumps(policy))
    log(f"granted ApplyGuardrail on {state['guardrail_arn'].rsplit('/', 1)[-1]} to {role_name}", "ok")
    (SUBMISSION / "iam" / "after" / f"{role_name}__{APPLY_POLICY_NAME}.json").write_text(
        json.dumps(policy, indent=2), encoding="utf-8")


def set_guardrail_on_harness(cfg, state, attach: bool) -> dict:
    """Read-modify-write the harness so no other configuration is disturbed."""
    need(state, "harness_id")
    ctl = client("bedrock-agentcore-control", cfg)
    harness = ctl.get_harness(harnessId=state["harness_id"])["harness"]

    fields = updatable_fields(ctl)
    payload = {k: v for k, v in harness.items() if k in fields and v is not None}

    model = payload.get("model") or {}
    bedrock_cfg = model.get("bedrockModelConfig")
    if not bedrock_cfg:
        die("harness is not using a Bedrock model - guardrailConfig does not apply")

    extra = dict(bedrock_cfg.get("additionalParams") or {})
    if attach:
        need(state, "guardrail_arn", "guardrail_version")
        extra["guardrailConfig"] = {
            "guardrailIdentifier": state["guardrail_arn"],
            "guardrailVersion": str(state["guardrail_version"]),
            # trace=enabled is what puts intervention detail into the response
            # and the invocation logs. Without it, monitoring has nothing to
            # count and Task 6's alert conditions cannot be built.
            "trace": "enabled",
        }
    else:
        extra.pop("guardrailConfig", None)

    bedrock_cfg = dict(bedrock_cfg)
    if extra:
        bedrock_cfg["additionalParams"] = extra
    else:
        bedrock_cfg.pop("additionalParams", None)
    payload["model"] = {"bedrockModelConfig": bedrock_cfg}

    tools_before = [t.get("type") for t in (payload.get("tools") or [])]

    # Recursively strip anything UpdateHarness will not accept, then drop any
    # top-level field left empty by that pruning.
    update_shape = ctl.meta.service_model.operation_model("UpdateHarness").input_shape
    payload = {k: v for k, v in prune_to_shape(payload, update_shape).items()
               if not (isinstance(v, (dict, list)) and not v)}
    log(f"sending fields: {sorted(payload)}")

    ctl.update_harness(harnessId=state["harness_id"], **payload)
    log(f"harness updated - guardrail {'attached' if attach else 'detached'}", "ok")

    time.sleep(3)
    after = ctl.get_harness(harnessId=state["harness_id"])["harness"]
    after_extra = ((after.get("model") or {}).get("bedrockModelConfig", {})
                   .get("additionalParams") or {})
    tools_after = [t.get("type") for t in (after.get("tools") or [])]

    has_guardrail = "guardrailConfig" in after_extra
    if has_guardrail != attach:
        die(f"verification failed: guardrailConfig present={has_guardrail}, expected {attach}")
    if tools_before != tools_after:
        die(f"tools changed during update: {tools_before} -> {tools_after} - restore before testing")
    log(f"verified: guardrailConfig={'present' if has_guardrail else 'absent'}, "
        f"tools intact {tools_after}", "ok")

    after.pop("ResponseMetadata", None)
    write_evidence(f"harness_guardrail_{'attached' if attach else 'detached'}.json",
                   after, subdir="discovery")
    update_state(guardrail_attached=attach)
    return after


def show_status(cfg, state) -> None:
    ctl = client("bedrock-agentcore-control", cfg)
    if not state.get("harness_id"):
        die("no harness in state.json")
    harness = ctl.get_harness(harnessId=state["harness_id"])["harness"]
    extra = ((harness.get("model") or {}).get("bedrockModelConfig", {})
             .get("additionalParams") or {})
    guardrail = extra.get("guardrailConfig")
    log(f"harness {harness.get('harnessName')} status={harness.get('status')}")
    log(f"  model {(harness.get('model') or {}).get('bedrockModelConfig', {}).get('modelId')}")
    log(f"  tools {[t.get('type') for t in harness.get('tools', [])]}")
    if guardrail:
        log(f"  guardrail ATTACHED version={guardrail.get('guardrailVersion')} "
            f"trace={guardrail.get('trace')}", "ok")
    else:
        log("  guardrail NOT attached")

    role_name = role_name_from_arn(state["harness_role_arn"]) if state.get("harness_role_arn") else None
    if role_name:
        try:
            client("iam", cfg).get_role_policy(RoleName=role_name, PolicyName=APPLY_POLICY_NAME)
            log(f"  {role_name} has {APPLY_POLICY_NAME}", "ok")
        except ClientError:
            log(f"  {role_name} is MISSING {APPLY_POLICY_NAME} - requests will 403", "warn")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--create", action="store_true")
    ap.add_argument("--attach", action="store_true")
    ap.add_argument("--detach", action="store_true")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()
    if not any((args.create, args.attach, args.detach, args.status)):
        ap.error("choose at least one of --create --attach --detach --status")
    if args.attach and args.detach:
        ap.error("--attach and --detach are mutually exclusive")

    cfg, state = load_config(), load_state()

    if args.create:
        create_guardrail(cfg, state)
        state = load_state()
    if args.attach:
        grant_apply_permission(cfg, state)
        log("waiting 10s for the IAM grant to propagate before attaching", "step")
        time.sleep(10)
        set_guardrail_on_harness(cfg, state, attach=True)
    if args.detach:
        set_guardrail_on_harness(cfg, state, attach=False)
    if args.status:
        show_status(cfg, load_state())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
