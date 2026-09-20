#!/usr/bin/env python3
"""Prove the applied IAM state is least-privilege, at the policy level.

WHY THIS EXISTS
---------------
`20_harden_iam.py --verify` ran a smoke test: it confirmed the agent still
answered with retrieval after narrowing. That is necessary and completely
blind to the failure that actually happened -- four logging statements were
WIDENED, and the agent kept working perfectly, because widening a permission
never breaks anything. Behavioural verification cannot detect a widening.

So this script asserts on the policy instead of on the service. It answers the
two questions a reviewer actually has about an after-state:

  1. Did any statement end up granting more than it started with?
  2. Is every surviving wildcard justified -- and justified with evidence,
     not with an adjective?

It is offline by default: it replays the captured before/after evidence and
needs no AWS credentials. `--live` reads the after-state from IAM instead, so
the same checks run against what is really deployed.

Exit codes: 0 clean | 4 a statement widened | 5 a wildcard is unjustified
"""
from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ns_common import SUBMISSION, client, log, whoami  # noqa: E402

IAM_DIR = SUBMISSION / "iam"
BEFORE_DIR = IAM_DIR / "before"
AFTER_DIR = IAM_DIR / "after"
REGISTER = IAM_DIR / "wildcard-register.json"


def _load_harden():
    """Import is_narrower from 20_harden_iam.py (module name starts with a digit)."""
    path = Path(__file__).resolve().parent / "20_harden_iam.py"
    spec = importlib.util.spec_from_file_location("harden", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HARDEN = _load_harden()
is_narrower = HARDEN.is_narrower
_arn_covers = HARDEN._arn_covers


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def action_is_narrower(before: list[str], after: list[str]) -> bool:
    """Same containment test as resources, over action strings.

    IAM actions wildcard the same way ARNs do (`xray:Put*`), so a literal set
    comparison would wrongly flag `xray:PutTraceSegments` as newly added when
    the original statement said `xray:Put*`.
    """
    return all(any(_arn_covers(b, a) for b in before) for a in after)


def index_statements(doc: dict) -> dict[str, dict]:
    """Map Sid -> statement. Sid-less statements get a positional key."""
    out = {}
    for i, stmt in enumerate(doc.get("Statement", [])):
        out[stmt.get("Sid") or f"__unnamed_{i}"] = stmt
    return out


def compare_policy(role_kind: str, policy_name: str,
                   before_doc: dict, after_doc: dict) -> list[dict]:
    """One verdict row per statement."""
    before_s = index_statements(before_doc)
    after_s = index_statements(after_doc)
    rows = []

    for sid, after_stmt in after_s.items():
        before_stmt = before_s.get(sid)
        a_res = _as_list(after_stmt.get("Resource"))
        a_act = _as_list(after_stmt.get("Action"))
        if before_stmt is None:
            rows.append({
                "role": role_kind, "policy": policy_name, "sid": sid,
                "verdict": "ADDED", "widened": True,
                "detail": "statement exists in AFTER but not in BEFORE",
                "after_resources": a_res, "after_actions": a_act,
            })
            continue
        b_res = _as_list(before_stmt.get("Resource"))
        b_act = _as_list(before_stmt.get("Action"))

        res_ok = is_narrower(b_res, a_res)
        act_ok = action_is_narrower(b_act, a_act)
        widened = not (res_ok and act_ok)

        detail: list[str] = []
        if widened:
            if not res_ok:
                extra = [r for r in a_res if not any(_arn_covers(b, r) for b in b_res)]
                detail.append(f"resources not covered by BEFORE: {extra}")
            if not act_ok:
                extra = [a for a in a_act if not any(_arn_covers(b, a) for b in b_act)]
                detail.append(f"actions not present in BEFORE: {extra}")
            verdict = "WIDENED"
        elif a_res == b_res and a_act == b_act:
            verdict = "UNCHANGED"
            detail.append("identical to the console original")
        else:
            verdict = "NARROWED"
            if a_res != b_res:
                detail.append(f"resources {len(b_res)} -> {len(a_res)}")
            if a_act != b_act:
                removed = [a for a in b_act if a not in a_act]
                detail.append(f"actions removed: {len(removed)}")

        rows.append({
            "role": role_kind, "policy": policy_name, "sid": sid,
            "verdict": verdict, "widened": widened, "detail": "; ".join(detail),
            "before_resources": b_res, "after_resources": a_res,
            "before_actions": b_act, "after_actions": a_act,
        })

    for sid in before_s:
        if sid not in after_s:
            rows.append({
                "role": role_kind, "policy": policy_name, "sid": sid,
                "verdict": "REMOVED", "widened": False,
                "detail": "statement deleted entirely",
                "before_resources": _as_list(before_s[sid].get("Resource")),
                "before_actions": _as_list(before_s[sid].get("Action")),
                "after_resources": [], "after_actions": [],
            })
    return rows


# ---------------------------------------------------------------------------
# Wildcard register
# ---------------------------------------------------------------------------

VALID_CLASSES = {"UNAVOIDABLE", "NECESSARY", "SCOPED"}


def find_wildcards(rows: list[dict]) -> list[dict]:
    """Every surviving resource containing a `*`, bare or partial."""
    out = []
    for row in rows:
        if row["verdict"] == "REMOVED":
            continue
        for res in row.get("after_resources", []):
            if "*" in res:
                out.append({
                    "role": row["role"], "sid": row["sid"], "resource": res,
                    "kind": "bare" if res == "*" else "partial",
                    "actions": row.get("after_actions", []),
                })
    return out


def is_covered(actual: str, registered: str) -> bool:
    return actual == registered or fnmatch.fnmatchcase(actual, registered)


def apply_intentional_grants(rows: list[dict], register: dict) -> list[dict]:
    """Reclassify a widening that was deliberate and is argued in the register.

    Hardening is not purely subtractive. Adding `bedrock:ApplyGuardrail` on the
    cross-Region guardrail-profile ARNs is a real new grant, and the system does
    not work without it. The honest treatment is not to exempt such a change
    from the check but to require it to be DECLARED: every resource the original
    did not cover must be named in `intentional_grants`, with a reason. An
    undeclared widening still fails.
    """
    grants = register.get("intentional_grants", {})
    for row in rows:
        if not row["widened"]:
            continue
        entry = grants.get(f"{row['role']}/{row['sid']}")
        if entry is None:
            continue
        before = row.get("before_resources", [])
        uncovered = [r for r in row.get("after_resources", [])
                     if not any(_arn_covers(b, r) for b in before)]
        declared = entry.get("added_resources", [])
        undeclared = [r for r in uncovered
                      if not any(is_covered(r, d) for d in declared)]
        if undeclared:
            row["detail"] += f"; NOT declared in intentional_grants: {undeclared}"
            continue
        row["verdict"] = "WIDENED-DECLARED"
        row["widened"] = False
        row["declared_reason"] = entry.get("reason", "")
        row["net_effect"] = entry.get("net_effect", "")
        row["detail"] = (f"declared new grant: {uncovered}. "
                         f"{entry.get('net_effect', '')}")
    return rows


def audit_wildcards(wildcards: list[dict], register: dict) -> list[dict]:
    """Every wildcard must have a register entry, classified and evidenced.

    A wildcard with no entry FAILS rather than defaulting to pass. That is the
    whole point: the earlier draft's wildcard count matched only bare
    `Resource: "*"`, so seven partial wildcards were never accounted for and
    the summary table claimed the gateway role had reached zero.
    """
    entries = register.get("entries", {})
    results = []
    for wc in wildcards:
        key = f"{wc['role']}/{wc['sid']}"
        entry = entries.get(key)
        if entry is None:
            results.append({**wc, "classification": "UNJUSTIFIED", "justified": False,
                            "reason": f"no entry for '{key}' in wildcard-register.json"})
            continue
        cls = entry.get("classification")
        if cls not in VALID_CLASSES:
            results.append({**wc, "classification": cls or "MISSING", "justified": False,
                            "reason": f"classification must be one of {sorted(VALID_CLASSES)}"})
            continue
        if cls == "NECESSARY" and not entry.get("evidence"):
            results.append({**wc, "classification": cls, "justified": False,
                            "reason": "NECESSARY requires an 'evidence' pointer to an "
                                      "ablation run showing removal breaks the system"})
            continue
        pattern = entry.get("resource_pattern", wc["resource"])
        if not is_covered(wc["resource"], pattern):
            results.append({**wc, "classification": cls, "justified": False,
                            "reason": f"live resource {wc['resource']!r} does not match "
                                      f"registered pattern {pattern!r}"})
            continue
        results.append({**wc, "classification": cls, "justified": True,
                        "reason": entry.get("reason", ""),
                        "evidence": entry.get("evidence")})
    return results


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def role_kind_of(role_name: str) -> str:
    lowered = role_name.lower()
    if "harness" in lowered:
        return "harness"
    if "gateway" in lowered:
        return "gateway"
    if "knowledge" in lowered:
        return "kb"
    if "logging" in lowered:
        return "logging"
    return role_name


def policy_pairs_offline() -> list[tuple[str, str, dict, dict]]:
    """(role_kind, policy_name, before_doc, after_doc) from captured evidence."""
    pairs = []
    for after_path in sorted(AFTER_DIR.glob("*.json")):
        before_path = BEFORE_DIR / after_path.name
        if not before_path.exists():
            log(f"no BEFORE for {after_path.name} - created by hardening, skipped", "warn")
            continue
        before_raw = json.loads(before_path.read_text(encoding="utf-8"))
        after_raw = json.loads(after_path.read_text(encoding="utf-8"))
        role_name, _, policy_name = after_path.stem.partition("__")
        pairs.append((role_kind_of(role_name),
                      policy_name.replace("managed__", ""),
                      before_raw.get("document", before_raw),
                      after_raw.get("document", after_raw)))
    return pairs


def policy_pairs_live(save: bool = False) -> list[tuple[str, str, dict, dict]]:
    """BEFORE from captured evidence, AFTER read back from IAM right now."""
    iam = client("iam")
    pairs = []
    if save:
        AFTER_DIR.mkdir(parents=True, exist_ok=True)
    for before_path in sorted(BEFORE_DIR.glob("*.json")):
        role_name, _, stem = before_path.stem.partition("__")
        before_raw = json.loads(before_path.read_text(encoding="utf-8"))
        before_doc = before_raw.get("document", before_raw)
        try:
            if stem.startswith("managed__"):
                arn = before_raw["arn"]
                default = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                after_doc = iam.get_policy_version(
                    PolicyArn=arn, VersionId=default)["PolicyVersion"]["Document"]
                policy_name = stem[len("managed__"):]
            else:
                after_doc = iam.get_role_policy(
                    RoleName=role_name, PolicyName=stem)["PolicyDocument"]
                policy_name = stem
        except Exception as exc:
            log(f"cannot read live policy for {role_name}/{stem}: {exc}", "err")
            continue
        if save:
            out = AFTER_DIR / before_path.name
            payload = ({"arn": before_raw["arn"], "document": after_doc}
                       if stem.startswith("managed__") else after_doc)
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        pairs.append((role_kind_of(role_name), policy_name, before_doc, after_doc))
    if save:
        log(f"saved {len(pairs)} live policy document(s) to iam/after/", "ok")
    return pairs


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_markdown(payload: dict, path: Path) -> None:
    s = payload["summary"]
    L = ["# IAM after-state audit\n",
         f"Source: **{payload['source']}** | Account: `{payload.get('account') or 'n/a'}` "
         f"| Generated: {payload['generated']}\n",
         f"**Verdict: {payload['verdict']}**\n",
         f"- Statements compared: {s['statements']}",
         f"- Narrowed: {s['narrowed']} | Removed: {s['removed']} | "
         f"Unchanged: {s['unchanged']}",
         f"- Widened but declared and argued: {s.get('widened_declared', 0)}",
         f"- **Widened, undeclared: {s['widened']}**",
         f"- Surviving wildcards: {s['wildcards']} ({s['wildcards_bare']} bare, "
         f"{s['wildcards_partial']} partial)",
         f"- **Unjustified wildcards: {s['wildcards_unjustified']}**\n"]

    if s["widened"]:
        L += ["## Widened statements - these fail the audit\n",
              "| Role | Statement | Detail |", "| --- | --- | --- |"]
        L += [f"| {r['role']} | `{r['sid']}` | {r['detail']} |"
              for r in payload["statements"] if r["widened"]]
        L.append("")

    declared = [r for r in payload["statements"] if r["verdict"] == "WIDENED-DECLARED"]
    if declared:
        L += ["## Declared new grants\n",
              "Additions the hardening makes deliberately. Each must name every "
              "resource the original did not cover, with a reason.\n",
              "| Role | Statement | Reason | Net effect |", "| --- | --- | --- | --- |"]
        L += [f"| {r['role']} | `{r['sid']}` | {r.get('declared_reason', '')} | "
              f"{r.get('net_effect', '')} |" for r in declared]
        L.append("")

    L += ["## Surviving wildcards\n",
          "| Role | Statement | Resource | Class | Justification |",
          "| --- | --- | --- | --- | --- |"]
    for w in payload["wildcards"]:
        mark = ("" if w["justified"] or w["classification"] == "UNJUSTIFIED"
                else " **(UNJUSTIFIED)**")
        L.append(f"| {w['role']} | `{w['sid']}` | `{w['resource']}` | "
                 f"{w['classification']}{mark} | {w.get('reason', '')} |")
    L.append("")

    L += ["## Every statement\n", "| Role | Statement | Verdict | Detail |",
          "| --- | --- | --- | --- |"]
    L += [f"| {r['role']} | `{r['sid']}` | {r['verdict']} | {r['detail']} |"
          for r in sorted(payload["statements"], key=lambda x: (x["role"], x["sid"]))]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="read the after-state from IAM instead of iam/after/")
    ap.add_argument("--out", default=str(IAM_DIR / "iam_after.json"))
    ap.add_argument("--save-after", action="store_true",
                    help="with --live, write the policies read back from IAM into "
                         "iam/after/. Needed whenever the deployed state has moved "
                         "on since --apply wrote those files -- otherwise the "
                         "offline audit judges a stale after-state.")
    ap.add_argument("--before", help="override the BEFORE directory")
    ap.add_argument("--after", help="override the AFTER directory")
    ap.add_argument("--expect-fail", action="store_true",
                    help="invert the exit code. Used to demonstrate that this "
                         "auditor really does catch the session-1 regression: "
                         "pointing it at iam/session1-2026-09-18/ must FAIL, and "
                         "with this flag that failure is the success condition.")
    args = ap.parse_args()

    global BEFORE_DIR, AFTER_DIR
    if args.before:
        BEFORE_DIR = Path(args.before)
    if args.after:
        AFTER_DIR = Path(args.after)

    if args.live:
        pairs = policy_pairs_live(save=args.save_after)
        source, account = "live IAM read-back", whoami().get("account", "")
    else:
        pairs = policy_pairs_offline()
        source, account = "captured iam/before vs iam/after", ""

    if not pairs:
        log("no policy pairs found - nothing to audit", "err")
        return 1

    rows: list[dict] = []
    for role_kind, policy_name, before_doc, after_doc in pairs:
        rows.extend(compare_policy(role_kind, policy_name, before_doc, after_doc))

    register = (json.loads(REGISTER.read_text(encoding="utf-8"))
                if REGISTER.exists() else {"entries": {}})
    rows = apply_intentional_grants(rows, register)
    wildcards = audit_wildcards(find_wildcards(rows), register)

    widened = [r for r in rows if r["widened"]]
    unjust = [w for w in wildcards if not w["justified"]]
    summary = {
        "statements": len(rows),
        "narrowed": sum(1 for r in rows if r["verdict"] == "NARROWED"),
        "removed": sum(1 for r in rows if r["verdict"] == "REMOVED"),
        "unchanged": sum(1 for r in rows if r["verdict"] == "UNCHANGED"),
        "widened_declared": sum(1 for r in rows if r["verdict"] == "WIDENED-DECLARED"),
        "widened": len(widened),
        "wildcards": len(wildcards),
        "wildcards_bare": sum(1 for w in wildcards if w["kind"] == "bare"),
        "wildcards_partial": sum(1 for w in wildcards if w["kind"] == "partial"),
        "wildcards_unjustified": len(unjust),
    }
    verdict = "PASS" if not widened and not unjust else "FAIL"
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source, "account": account, "verdict": verdict,
        "summary": summary, "statements": rows, "wildcards": wildcards,
    }

    out = Path(args.out)
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    write_markdown(payload, out.with_suffix(".md"))

    log(f"statements {summary['statements']}  narrowed {summary['narrowed']}  "
        f"removed {summary['removed']}  unchanged {summary['unchanged']}")
    log(f"wildcards {summary['wildcards']} ({summary['wildcards_bare']} bare, "
        f"{summary['wildcards_partial']} partial)")
    for r in widened:
        log(f"WIDENED {r['role']}/{r['sid']}: {r['detail']}", "err")
    for w in unjust:
        log(f"UNJUSTIFIED {w['role']}/{w['sid']} {w['resource']}: {w['reason']}", "err")
    log(f"wrote {out.name} and {out.with_suffix('.md').name}", "ok")

    if args.expect_fail:
        if verdict == "FAIL":
            log("expected FAIL and got one - the auditor detects this regression", "ok")
            return 0
        log("expected FAIL but the audit passed - the detector is not working", "err")
        return 6

    if widened:
        log(f"AUDIT FAIL - {len(widened)} statement(s) grant more than before", "err")
        return 4
    if unjust:
        log(f"AUDIT FAIL - {len(unjust)} wildcard(s) without justification", "err")
        return 5
    log("AUDIT PASS - nothing widened, every wildcard justified", "ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
