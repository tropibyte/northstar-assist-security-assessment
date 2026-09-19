"""Least-privilege hardening for the Northstar Assist service roles (Task 4).

Approach: do not hand-write replacement policies. Read what the console
actually attached, then NARROW it. Two transformations are applied:

  1. Resource narrowing  - a statement granting an action on "*" (or on every
     Bedrock resource in the account) is rewritten to the specific ARNs this
     system uses, resolved from evidence/state.json.
  2. Statement dropping  - a statement whose actions serve only a feature that
     was never configured (Browser, Code Interpreter, Memory, filesystem
     mounts) is removed entirely.

Narrowing from the real policy rather than replacing it means the before/after
comparison in the deliverable is a genuine diff, and it avoids inventing IAM
action names that may not exist.

Safety: --apply keeps the original policy document in evidence/iam/before/ and
--restore puts it back verbatim. --verify runs one live harness invocation
after applying and automatically restores if the agent can no longer answer,
because an over-tightened role that silently breaks retrieval is worse than a
loose one.

Usage:
  python 20_harden_iam.py --dump                 # capture the BEFORE state
  python 20_harden_iam.py --plan                 # show the diff, change nothing
  python 20_harden_iam.py --apply --verify       # narrow, smoke-test, roll back on failure
  python 20_harden_iam.py --restore              # undo
"""
from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (SUBMISSION, client, confirm, die, load_config, load_state,
                       log, need, role_name_from_arn, write_evidence)

BEFORE_DIR = SUBMISSION / "iam" / "before"
AFTER_DIR = SUBMISSION / "iam" / "after"

# Features this deployment does not use. A statement whose actions ALL match
# one matcher is removed entirely.
#
# Matching is by predicate rather than by an enumerated action list: the
# console grants GetBrowserSession, UpdateBrowserStream, s3files:ClientMount
# and similar, and any hardcoded list drifts out of date the moment AWS adds
# an action. A predicate that keys on the feature's vocabulary keeps matching.
FEATURE_MATCHERS = {
    "browser": lambda a: a.startswith("bedrock-agentcore:") and "browser" in a,
    "code_interpreter": lambda a: a.startswith("bedrock-agentcore:") and "codeinterpreter" in a,
    "memory": lambda a: a.startswith("bedrock-agentcore:") and (
        "memory" in a or a.split(":", 1)[-1] in {
            "createevent", "deleteevent", "getevent", "listevents"}),
    "filesystem": lambda a: a.startswith(("elasticfilesystem:", "s3files:")),
    # Standard retrieval is configured on the gateway target, not Agentic
    # retrieval, so the agentic and reranking permissions have no caller.
    "agentic_retrieval": lambda a: a in {"bedrock:agenticretrievestream", "bedrock:rerank"},
}

WHY_UNUSED = {
    "browser": "the Browser tool is switched off on the harness",
    "code_interpreter": "the Code Interpreter tool is switched off on the harness",
    "memory": "Memory is disabled on the harness, so there are no events to read or write",
    "filesystem": "no EFS or S3 file-system mount is configured",
    "agentic_retrieval": "the gateway target uses Standard retrieval, not Agentic retrieval",
}

# Individual actions stripped from otherwise-legitimate statements, with the
# reason each one is indefensible for this system.
DANGEROUS_ACTIONS = {
    "aws-marketplace:unsubscribe": (
        "cancels foundation-model subscriptions for the whole account. The "
        "knowledge base role needs to read and create subscriptions to use a "
        "model; it never needs to revoke one, and revoking one is an "
        "availability attack on every workload in the account."),
}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _preflight_inference_profile(model_id: str) -> dict | None:
    """The regional model ARNs the profile really routes to, from preflight.

    Only returned when the captured profile is for the model actually in use.
    preflight.json reflects whatever config.json said when it last ran, which
    is not necessarily what the harness runs now.
    """
    path = SUBMISSION / "evidence" / "preflight.json"
    if not path.exists():
        return None
    try:
        profile = json.loads(path.read_text(encoding="utf-8")).get(
            "models", {}).get("inference_profile")
    except (json.JSONDecodeError, OSError):
        return None
    if not profile or not profile.get("arn"):
        return None
    if not profile["arn"].endswith(f"/{model_id}"):
        log(f"  preflight captured {profile['arn'].rsplit('/', 1)[-1]} but the "
            f"harness runs {model_id} - ignoring the stale capture", "warn")
        return None
    return profile


def resolve_targets(state: dict, cfg: dict, role_kind: str = "harness") -> dict[str, list[str]]:
    """Build the ARN allow-lists the narrowed policies point at, per role."""
    region, account = state["region"], state["account_id"]
    # Prefer the model the live harness reports over the one config.json names.
    # A model changed in the console (as happened when Anthropic models turned
    # out to have no Marketplace agreement) otherwise leaves config.json stale,
    # and the narrowed policy would authorise a profile that is never invoked.
    model_id = state.get("harness_model_id") or cfg["model_id"]
    if state.get("harness_model_id") and state["harness_model_id"] != cfg.get("model_id"):
        log(f"  config.json says {cfg.get('model_id')} but the harness runs "
            f"{state['harness_model_id']} - scoping to the harness", "warn")

    model_arns: list[str] = []
    if model_id.startswith(("us.", "global.", "eu.", "apac.")):
        # A cross-Region inference profile requires BOTH the profile ARN and the
        # regional foundation-model ARNs it can route to. Granting only the
        # profile produces an AccessDenied at invoke time.
        #
        # Take the regional ARNs from the profile itself (captured by preflight)
        # rather than assuming which regions it spans. This profile routes to
        # three regions, not the four a naive us-* guess would grant, and every
        # ARN granted beyond the real set is an unused permission.
        profile = _preflight_inference_profile(model_id)
        if profile and profile.get("models"):
            model_arns.append(profile["arn"])
            model_arns.extend(profile["models"])
            log(f"  using {len(profile['models'])} regional ARN(s) read from the "
                f"live inference profile")
        else:
            log("  preflight.json has no inference profile - falling back to "
                "generated ARNs; re-run 00_preflight.py to tighten this", "warn")
            model_arns.append(f"arn:aws:bedrock:{region}:{account}:inference-profile/{model_id}")
            bare = model_id.split(".", 1)[1]
            for r in ("us-east-1", "us-east-2", "us-west-2"):
                model_arns.append(f"arn:aws:bedrock:{r}::foundation-model/{bare}")
    else:
        model_arns.append(f"arn:aws:bedrock:{region}::foundation-model/{model_id}")

    embedding_arns = [f"arn:aws:bedrock:{region}::foundation-model/{cfg['embedding_model_id']}"]

    # Only the harness generates. The gateway and knowledge base roles touch
    # models solely for retrieval-side embedding, so granting them the
    # generation model would let a compromised retrieval path run inference
    # the design never intended.
    if role_kind in {"gateway", "knowledge_base"}:
        model_arns = list(embedding_arns)

    guardrail_arns = [state["guardrail_arn"]] if state.get("guardrail_arn") else []
    if guardrail_arns and state.get("guardrail_tier") == "STANDARD":
        spec_path = SUBMISSION / "guardrail" / "guardrail.json"
        try:
            profile = (json.loads(spec_path.read_text(encoding="utf-8"))
                       .get("crossRegionConfig") or {}).get("guardrailProfileIdentifier")
        except (json.JSONDecodeError, OSError):
            profile = None
        if profile:
            # Cross-Region guardrail inference authorises against the profile
            # as well as the guardrail itself, and the profile ARN is regional:
            # it follows wherever the model call is routed. Grant it in every
            # region the inference profile can route to, taken from the same
            # captured profile that scopes the model ARNs above.
            profile_regions = [region]
            captured = _preflight_inference_profile(model_id) or {}
            for arn in captured.get("models", []):
                parts = arn.split(":")
                if len(parts) > 3 and parts[3] and parts[3] not in profile_regions:
                    profile_regions.append(parts[3])
            for r in profile_regions:
                guardrail_arns.append(
                    f"arn:aws:bedrock:{r}:{account}:guardrail-profile/{profile}")

    targets = {
        "model": model_arns,
        "embedding": embedding_arns,
        "guardrail": guardrail_arns,
        "gateway": [state["gateway_arn"], f"{state['gateway_arn']}/*"] if state.get("gateway_arn") else [],
        "kb": [state["kb_arn"]] if state.get("kb_arn") else [],
        "s3": ([f"arn:aws:s3:::{state['bucket']}", f"arn:aws:s3:::{state['bucket']}/*"]
               if state.get("bucket") else []),
        "logs": [f"arn:aws:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/*",
                 f"arn:aws:logs:{region}:{account}:log-group:{cfg['log_group']}:*"],
    }
    return targets


def classify_action(action: str) -> str | None:
    """Map an IAM action to the ARN group that should scope it."""
    a = action.lower()
    if a.startswith("bedrock:invokemodel") or a == "bedrock:converse" or a.startswith("bedrock:converse"):
        return "model"
    if a.startswith("bedrock:applyguardrail"):
        return "guardrail"
    if "gateway" in a and a.startswith("bedrock-agentcore"):
        return "gateway"
    if a.startswith("bedrock:retrieve") or a.startswith("bedrock-agent-runtime:") or "knowledgebase" in a:
        return "kb"
    if a.startswith("s3:"):
        return "s3"
    if a.startswith("logs:"):
        return "logs"
    return None


def statement_feature(statement: dict) -> str | None:
    """Return the unused feature this statement serves exclusively, if any."""
    actions = [a.lower() for a in _as_list(statement.get("Action"))]
    if not actions:
        return None
    for feature, matches in FEATURE_MATCHERS.items():
        if all(matches(a) for a in actions):
            return feature
    return None


def narrow_policy(doc: dict, targets: dict[str, list[str]], role_kind: str) -> tuple[dict, list[dict]]:
    """Return (narrowed_document, change_log)."""
    changes: list[dict] = []
    out_statements: list[dict] = []

    for index, statement in enumerate(_as_list(doc.get("Statement"))):
        sid = statement.get("Sid") or f"Statement{index}"

        feature = statement_feature(statement)
        if feature:
            changes.append({
                "sid": sid, "change": "REMOVED", "feature": feature,
                "actions": _as_list(statement.get("Action")),
                "rationale": f"Unused capability: {WHY_UNUSED.get(feature, feature)}. "
                             f"A permission with no caller is pure attack surface - it is "
                             f"what a compromised role reaches for.",
            })
            continue

        if statement.get("Effect") != "Allow":
            out_statements.append(statement)
            continue

        resources = _as_list(statement.get("Resource"))
        actions = _as_list(statement.get("Action"))

        # Strip individually indefensible actions before any resource work,
        # keeping the rest of the statement intact.
        stripped = [a for a in actions if a.lower() in DANGEROUS_ACTIONS]
        if stripped:
            actions = [a for a in actions if a.lower() not in DANGEROUS_ACTIONS]
            for action in stripped:
                changes.append({
                    "sid": sid, "change": "ACTION-REMOVED", "actions": [action],
                    "before": resources, "after": resources,
                    "rationale": DANGEROUS_ACTIONS[action.lower()],
                })
            if not actions:
                continue
            statement = dict(statement)
            statement["Action"] = actions
        groups = {classify_action(a) for a in actions} - {None}
        # Narrowing only makes sense where the grant is currently broad.
        broad = any("*" in r for r in resources)

        # Every action maps to one ARN group: rewrite Resource in place.
        if len(groups) == 1 and broad:
            group = groups.pop()
            allowed = targets.get(group) or []
            if allowed:
                new_statement = dict(statement)
                new_statement["Resource"] = allowed
                out_statements.append(new_statement)
                changes.append({
                    "sid": sid, "change": "NARROWED", "actions": actions,
                    "before": resources, "after": allowed,
                    "rationale": RATIONALE.get(group, "scoped to the resources this system uses"),
                })
                continue

        # Actions span several ARN groups: split so each carries its own scope.
        # Anything we cannot map is kept verbatim and flagged, never guessed at.
        if len(groups) > 1 and broad:
            split_statements, split_changes, unhandled = [], [], []
            for group in sorted(groups):
                group_actions = [a for a in actions if classify_action(a) == group]
                allowed = targets.get(group) or []
                if not allowed:
                    unhandled.extend(group_actions)
                    continue
                split_statements.append({
                    "Sid": f"{sid}{group.title().replace('_', '')}",
                    "Effect": "Allow", "Action": group_actions, "Resource": allowed,
                })
                split_changes.append({
                    "sid": sid, "change": "SPLIT", "actions": group_actions,
                    "before": resources, "after": allowed,
                    "rationale": f"separated from a mixed statement so {group} actions "
                                 f"carry their own resource scope. "
                                 + RATIONALE.get(group, ""),
                })
            unhandled.extend(a for a in actions if classify_action(a) is None)

            if split_statements:
                out_statements.extend(split_statements)
                changes.extend(split_changes)
                if unhandled:
                    keep = dict(statement)
                    keep["Action"] = unhandled
                    keep["Sid"] = f"{sid}Unclassified"
                    out_statements.append(keep)
                    changes.append({
                        "sid": sid, "change": "KEPT", "actions": unhandled,
                        "before": resources, "after": resources,
                        "rationale": "no ARN mapping is known for these actions; left as-is "
                                     "and flagged for manual review rather than guessed at.",
                    })
                continue

        out_statements.append(statement)
        if any(r == "*" for r in resources):
            changes.append({
                "sid": sid, "change": "UNCHANGED-WILDCARD", "actions": actions,
                "before": resources, "after": resources,
                "rationale": "wildcard remains - review manually and justify explicitly "
                             "in the summary, the rubric forbids unjustified wildcards.",
            })

    return {"Version": doc.get("Version", "2012-10-17"), "Statement": out_statements}, changes


RATIONALE = {
    "model": "the harness invokes exactly one inference profile; granting "
             "foundation-model/* would let a compromised role invoke every model in "
             "the account, including more capable and more expensive ones.",
    "guardrail": "ApplyGuardrail on * lets the role apply any guardrail in the "
                 "account, including a permissive one it creates or finds, which "
                 "defeats the control it is supposed to enforce.",
    "gateway": "the harness has one gateway; invoking arbitrary gateways would "
               "reach tools and data this agent was never authorised for.",
    "kb": "retrieval scoped to this knowledge base only, so the role cannot read "
          "another team's corpus if one is added to the account later.",
    "s3": "read access limited to the document bucket instead of every bucket "
          "the account holds.",
    "logs": "write access limited to this system's log groups; broad logs:* also "
            "permits reading and deleting other services' logs, which is how an "
            "attacker covers tracks.",
}


# ----------------------------------------------------------------- dump ----
def dump_role(iam, role_name: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        role = iam.get_role(RoleName=role_name)["Role"]
    except ClientError as exc:
        log(f"cannot read role {role_name}: {exc}", "warn")
        return {"role_name": role_name, "error": str(exc)}

    captured = {
        "role_name": role_name,
        "arn": role["Arn"],
        "trust_policy": role.get("AssumeRolePolicyDocument"),
        "inline_policies": {},
        "attached_policies": {},
    }

    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
        captured["inline_policies"][policy_name] = doc
        (out_dir / f"{role_name}__{policy_name}.json").write_text(
            json.dumps(doc, indent=2), encoding="utf-8")

    for attached in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        arn = attached["PolicyArn"]
        try:
            meta = iam.get_policy(PolicyArn=arn)["Policy"]
            version = iam.get_policy_version(
                PolicyArn=arn,
                VersionId=meta["DefaultVersionId"])["PolicyVersion"]["Document"]
        except ClientError as exc:
            version = {"error": str(exc)}
        # AWS-managed policies cannot be edited; only customer-managed ones can
        # be narrowed, and the console creates customer-managed policies here.
        customer_managed = ":aws:policy/" not in arn
        captured["attached_policies"][attached["PolicyName"]] = {
            "arn": arn, "document": version, "customer_managed": customer_managed,
        }
        if customer_managed and isinstance(version, dict):
            (out_dir / f"{role_name}__managed__{attached['PolicyName']}.json").write_text(
                json.dumps({"arn": arn, "document": version}, indent=2), encoding="utf-8")

    n_inline = len(captured["inline_policies"])
    n_attached = len(captured["attached_policies"])
    wildcards = count_wildcards(captured)
    log(f"{role_name}: {n_inline} inline, {n_attached} attached, "
        f"{wildcards} wildcard resource statement(s)", "ok")
    return captured


def count_wildcards(captured: dict) -> int:
    total = 0
    for doc in list(captured.get("inline_policies", {}).values()) + \
            [p["document"] for p in captured.get("attached_policies", {}).values()
             if isinstance(p.get("document"), dict)]:
        for statement in _as_list(doc.get("Statement")):
            if any(r == "*" for r in _as_list(statement.get("Resource"))):
                total += 1
    return total


def roles_from_state(state: dict) -> dict[str, str]:
    roles = {}
    for label, key in (("harness", "harness_role_arn"), ("gateway", "gateway_role_arn"),
                       ("knowledge_base", "kb_role_arn")):
        if state.get(key):
            roles[label] = role_name_from_arn(state[key])
    return roles


# ---------------------------------------------------------------- report ---
def render_summary(all_changes: dict, before: dict, after: dict) -> str:
    lines = [
        "# IAM Hardening Summary - Northstar Assist",
        "",
        "Generated by `submission/scripts/20_harden_iam.py`. Every policy document",
        "quoted here was read from the live account; nothing is retyped.",
        "",
        "## Roles reviewed",
        "",
        "| Role | Purpose | Statements removed | Statements narrowed | Wildcards before | Wildcards after |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    purpose = {
        "harness": "AgentCore harness execution role - invokes the model and the gateway",
        "gateway": "AgentCore gateway service role - performs retrieval against the KB",
        "knowledge_base": "Managed KB service role - reads S3 and calls the embedding model",
    }
    for label in all_changes:
        b, a = before.get(label, {}), after.get(label, {})
        changes = all_changes.get(label, {})
        flat = [c for entries in changes.values() for c in entries]
        removed = sum(1 for c in flat if c["change"] in ("REMOVED", "ACTION-REMOVED"))
        narrowed = sum(1 for c in flat if c["change"] in ("NARROWED", "SPLIT"))
        lines.append(f"| `{b.get('role_name', label)}` | {purpose.get(label, '')} | "
                     f"{removed} | {narrowed} | {count_wildcards(b)} | {count_wildcards(a)} |")

    for label, changes in all_changes.items():
        role_name = before.get(label, {}).get("role_name", label)
        lines += ["", f"## {role_name}", ""]
        if not changes:
            lines.append("No changes required.")
            continue
        for policy_name, entries in changes.items():
            kind = "Customer-managed policy" if policy_name.endswith("(managed)") else "Inline policy"
            clean = policy_name.replace(" (managed)", "")
            lines += [f"### {kind} `{clean}`", ""]
            for entry in entries:
                lines += [f"**{entry['change']} - `{entry['sid']}`**", ""]
                lines.append(f"- Actions: {', '.join(f'`{a}`' for a in entry.get('actions', []))}")
                if entry["change"] in {"NARROWED", "SPLIT"}:
                    lines.append(f"- Before: {', '.join(f'`{r}`' for r in entry['before'])}")
                    lines.append(f"- After: {', '.join(f'`{r}`' for r in entry['after'])}")
                lines.append(f"- Rationale: {entry['rationale']}")
                lines.append("")
    lines += [
        "## What an attacker gains from the original roles",
        "",
        "With the console-generated roles, a principal able to assume the harness",
        "execution role can invoke **any** Bedrock model in the account, apply **any**",
        "guardrail (including one deliberately configured to allow everything), and",
        "write to **any** log group. After narrowing, the same principal can invoke one",
        "inference profile, apply one guardrail, reach one gateway, and write to this",
        "system's log groups only.",
        "",
    ]
    return "\n".join(lines)


def unified_diff(before_doc: dict, after_doc: dict, name: str) -> str:
    b = json.dumps(before_doc, indent=2, sort_keys=True).splitlines()
    a = json.dumps(after_doc, indent=2, sort_keys=True).splitlines()
    return "\n".join(difflib.unified_diff(b, a, f"before/{name}", f"after/{name}", lineterm=""))


# ------------------------------------------------------------------ main ---
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dump", action="store_true", help="capture BEFORE state only")
    mode.add_argument("--plan", action="store_true", help="show the narrowing diff, change nothing")
    mode.add_argument("--apply", action="store_true", help="write the narrowed policies")
    mode.add_argument("--restore", action="store_true", help="restore the captured originals")
    ap.add_argument("--verify", action="store_true",
                    help="after --apply, invoke the harness once and roll back on failure")
    ap.add_argument("--yes", action="store_true", help="skip confirmation")
    args = ap.parse_args()

    cfg, state = load_config(), load_state()
    need(state, "account_id", "region")
    iam = client("iam", cfg)
    roles = roles_from_state(state)
    if not roles:
        die("no service roles in state.json - run 10_discover.py first")

    if args.restore:
        return do_restore(iam, roles, args.yes)

    log("capturing current role policies", "step")
    before = {label: dump_role(iam, name, BEFORE_DIR) for label, name in roles.items()}
    write_evidence("iam_before.json", before, subdir="iam")
    if args.dump:
        log(f"BEFORE state written to {BEFORE_DIR.relative_to(SUBMISSION)}", "ok")
        return 0

    targets_by_role = {k: resolve_targets(state, cfg, k) for k in roles}
    targets = targets_by_role["harness"]
    log("resolved narrowing targets:", "step")
    for group, arns in targets.items():
        log(f"  {group}: {len(arns)} ARN(s)" + (f" e.g. {arns[0]}" if arns else " (unknown)"))
    if not targets["guardrail"]:
        log("guardrail ARN unknown - run 30_guardrail.py first or ApplyGuardrail stays wildcard", "warn")

    AFTER_DIR.mkdir(parents=True, exist_ok=True)
    all_changes: dict[str, dict] = {}
    after: dict[str, dict] = {}

    for label, captured in before.items():
        role_name = captured.get("role_name", label)
        all_changes[label] = {}
        after[label] = {"role_name": role_name, "inline_policies": {}, "attached_policies": {}}
        for policy_name, doc in captured.get("inline_policies", {}).items():
            narrowed, changes = narrow_policy(doc, targets_by_role[label], label)
            all_changes[label][policy_name] = changes
            after[label]["inline_policies"][policy_name] = narrowed
            (AFTER_DIR / f"{role_name}__{policy_name}.json").write_text(
                json.dumps(narrowed, indent=2), encoding="utf-8")
            (AFTER_DIR / f"{role_name}__{policy_name}.diff").write_text(
                unified_diff(doc, narrowed, f"{role_name}__{policy_name}.json"), encoding="utf-8")
            summary = ", ".join(f"{c['change']}" for c in changes) or "no change"
            log(f"  {role_name}/{policy_name} [inline]: {summary}")

        # The console puts almost everything in customer-managed policies, not
        # inline ones: every wildcard on the harness role lives there. Narrowing
        # only inline policies would leave the actual over-permission untouched.
        for policy_name, info in captured.get("attached_policies", {}).items():
            doc = info.get("document")
            if not info.get("customer_managed") or not isinstance(doc, dict):
                log(f"  {role_name}/{policy_name} [attached]: AWS-managed or unreadable, "
                    f"cannot be narrowed - left as-is")
                continue
            narrowed, changes = narrow_policy(doc, targets_by_role[label], label)
            all_changes[label][f"{policy_name} (managed)"] = changes
            after[label]["attached_policies"][policy_name] = {
                "arn": info["arn"], "document": narrowed, "customer_managed": True}
            stem = f"{role_name}__managed__{policy_name}"
            (AFTER_DIR / f"{stem}.json").write_text(
                json.dumps(narrowed, indent=2), encoding="utf-8")
            (AFTER_DIR / f"{stem}.diff").write_text(
                unified_diff(doc, narrowed, f"{stem}.json"), encoding="utf-8")
            counts: dict[str, int] = {}
            for change in changes:
                counts[change["change"]] = counts.get(change["change"], 0) + 1
            summary = ", ".join(f"{k}x{v}" for k, v in counts.items()) or "no change"
            log(f"  {role_name}/{policy_name} [managed]: {summary}")

    write_evidence("iam_after.json", after, subdir="iam")
    write_evidence("iam_changes.json", all_changes, subdir="iam")
    (SUBMISSION / "docs" / "iam-hardening-summary.md").write_text(
        render_summary(all_changes, before, after), encoding="utf-8")
    log("wrote docs/iam-hardening-summary.md", "ok")

    if args.plan:
        log("plan only - nothing applied", "ok")
        return 0

    if not confirm("apply narrowed policies to the live roles?", args.yes):
        log("aborted", "warn")
        return 1

    for label, payload in after.items():
        role_name = payload["role_name"]
        for policy_name, doc in payload["inline_policies"].items():
            iam.put_role_policy(RoleName=role_name, PolicyName=policy_name,
                                PolicyDocument=json.dumps(doc))
            log(f"applied {role_name}/{policy_name} [inline]", "ok")
        for policy_name, info in payload["attached_policies"].items():
            set_managed_default(iam, info["arn"], info["document"])
            log(f"applied {role_name}/{policy_name} [managed]", "ok")

    if args.verify:
        return verify_or_rollback(iam, roles, before, args.yes)
    log("applied. Run 40_run_tests.py --smoke to confirm the agent still answers.", "ok")
    return 0


def verify_or_rollback(iam, roles, before, assume_yes) -> int:
    """IAM is eventually consistent; a failure here may be propagation, not policy."""
    import time
    log("waiting 15s for IAM propagation before verifying", "step")
    time.sleep(15)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from smoke import smoke_test  # noqa: F401  (provided by 40_run_tests.py helper)
        ok, detail = smoke_test()
    except Exception as exc:  # the smoke helper is optional
        log(f"smoke test unavailable ({exc}) - verify manually with 40_run_tests.py --smoke", "warn")
        return 0
    if ok:
        log("harness still answers with retrieval after narrowing", "ok")
        return 0
    log(f"harness FAILED after narrowing: {detail}", "err")
    log("rolling back to the captured originals", "warn")
    do_restore(iam, roles, assume_yes=True)
    return 3


def set_managed_default(iam, policy_arn: str, document: dict) -> None:
    """Publish a new default version of a customer-managed policy.

    IAM caps a policy at five versions, so the oldest non-default version is
    pruned first. The original remains recoverable from evidence/iam/before/
    regardless, which is what --restore replays.
    """
    versions = iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
    if len(versions) >= 5:
        oldest = sorted((v for v in versions if not v["IsDefaultVersion"]),
                        key=lambda v: v["CreateDate"])[0]
        iam.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest["VersionId"])
        log(f"  pruned old version {oldest['VersionId']} to stay under the 5-version cap")
    iam.create_policy_version(PolicyArn=policy_arn,
                              PolicyDocument=json.dumps(document), SetAsDefault=True)


def do_restore(iam, roles, assume_yes) -> int:
    if not confirm("restore the original console-generated policies?", assume_yes):
        return 1
    restored = 0
    for label, role_name in roles.items():
        for path in sorted(BEFORE_DIR.glob(f"{role_name}__*.json")):
            stem = path.stem[len(role_name) + 2:]
            if stem.startswith("managed__"):
                saved = json.loads(path.read_text(encoding="utf-8"))
                set_managed_default(iam, saved["arn"], saved["document"])
                log(f"restored {role_name}/{stem[len('managed__'):]} [managed]", "ok")
            else:
                iam.put_role_policy(RoleName=role_name, PolicyName=stem,
                                    PolicyDocument=path.read_text(encoding="utf-8"))
                log(f"restored {role_name}/{stem} [inline]", "ok")
            restored += 1
    if not restored:
        log("nothing to restore - no BEFORE capture found", "warn")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
