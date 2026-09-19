"""Ask the guardrail directly which policy fires on a given text.

The harness event stream carries no guardrail trace, so when a prompt is
blocked the responsible control has to be inferred. ApplyGuardrail can be
called on its own and returns the full assessment -- which topic, which content
filter, which regex, at what confidence -- so retuning is targeted at the
control that actually fired instead of the one that seems likely.

This is the difference between "FP-04 was probably the credential topic" and
knowing it was. It costs a guardrail text unit per call and no model tokens.

Usage:
  python 32_guardrail_probe.py --suite          # every false-positive prompt
  python 32_guardrail_probe.py --text "..."     # one ad-hoc string
  python 32_guardrail_probe.py --suite --source OUTPUT
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml
from botocore.exceptions import ClientError

from ns_common import (SUBMISSION, client, die, load_config, load_state, log,
                       need, write_evidence)

SUITE_PATH = SUBMISSION / "tests" / "prompts.yaml"


def probe(runtime, guardrail_id, version, text, source="INPUT",
          grounding_source: str | None = None, query: str | None = None) -> dict:
    """Apply the guardrail to a text, optionally with grounding context.

    Contextual grounding cannot be evaluated from an answer alone -- the policy
    compares the answer against a grounding_source and a query, supplied as
    separate qualified content blocks. Replaying a response without them
    silently skips the GROUNDING and RELEVANCE filters entirely, which is why
    text-only probes of output-blocked responses come back NONE.
    """
    content: list[dict] = []
    if grounding_source:
        content.append({"text": {"text": grounding_source,
                                 "qualifiers": ["grounding_source"]}})
    if query:
        content.append({"text": {"text": query, "qualifiers": ["query"]}})
    content.append({"text": {"text": text,
                             "qualifiers": ["guard_content"] if grounding_source else []}})
    try:
        r = runtime.apply_guardrail(
            guardrailIdentifier=guardrail_id, guardrailVersion=str(version),
            source=source, content=content)
    except ClientError as exc:
        return {"error": str(exc)}
    r.pop("ResponseMetadata", None)
    return r


def explain(result: dict) -> list[str]:
    """Reduce an assessment to the specific controls that fired."""
    reasons: list[str] = []
    for assessment in result.get("assessments", []):
        for topic in (assessment.get("topicPolicy") or {}).get("topics", []):
            if topic.get("action") in {"BLOCKED", "BLOCKED_TOPIC"} or topic.get("detected"):
                reasons.append(f"TOPIC '{topic.get('name')}' -> {topic.get('action')}")
        for flt in (assessment.get("contentPolicy") or {}).get("filters", []):
            if flt.get("detected") or flt.get("action") == "BLOCKED":
                reasons.append(f"CONTENT {flt.get('type')} "
                               f"conf={flt.get('confidence')} "
                               f"strength={flt.get('filterStrength')} -> {flt.get('action')}")
        word = assessment.get("wordPolicy") or {}
        for item in word.get("customWords", []) + word.get("managedWordLists", []):
            reasons.append(f"WORD {item.get('match') or item.get('type')} -> {item.get('action')}")
        sensitive = assessment.get("sensitiveInformationPolicy") or {}
        for pii in sensitive.get("piiEntities", []):
            reasons.append(f"PII {pii.get('type')} -> {pii.get('action')}")
        for rx in sensitive.get("regexes", []):
            reasons.append(f"REGEX '{rx.get('name')}' -> {rx.get('action')}")
        for cg in (assessment.get("contextualGroundingPolicy") or {}).get("filters", []):
            if cg.get("action") == "BLOCKED":
                reasons.append(f"GROUNDING {cg.get('type')} score={cg.get('score')} "
                               f"threshold={cg.get('threshold')}")
    return reasons


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", action="store_true",
                    help="probe every prompt whose expectation is 'answered'")
    ap.add_argument("--ids", help="comma-separated test IDs to probe instead")
    ap.add_argument("--text", help="probe one ad-hoc string")
    ap.add_argument("--responses",
                    help="comma-separated test IDs; probe their captured "
                         "responses on the OUTPUT path")
    ap.add_argument("--grounded", action="store_true",
                    help="with --responses, rebuild grounding_source and query from the "
                         "transcript so the GROUNDING/RELEVANCE filters are evaluated")
    ap.add_argument("--source", choices=["INPUT", "OUTPUT"], default="INPUT")
    args = ap.parse_args()

    cfg, state = load_config(), load_state()
    need(state, "guardrail_id")
    version = state.get("guardrail_version", "1")
    runtime = client("bedrock-runtime", cfg)

    cases: list[tuple[str, str, str | None, str | None]] = []
    if args.responses:
        # Probe the answers the agent actually produced, on the OUTPUT path.
        # An output-side block kills a response that was already composed, so
        # the only way to name the responsible control is to replay that exact
        # text -- which the transcripts preserved.
        args.source = "OUTPUT"
        wanted = {i.strip().upper() for i in args.responses.split(",")}
        folder = SUBMISSION / "evidence" / "transcripts" / "hardened"
        import json as _json
        for path in sorted(folder.glob("*.json")):
            record = _json.loads(path.read_text(encoding="utf-8"))
            if record["id"].upper() not in wanted:
                continue
            text = (record.get("text") or "").strip()
            if not text:
                log(f"  {path.stem}: no response text captured, skipping", "warn")
                continue
            ground = qry = None
            if args.grounded:
                raw = record.get("raw") or {}
                chunks: list[str] = []
                for call in raw.get("tool_calls", []):
                    for item in (call.get("payload") or []):
                        if isinstance(item, dict) and item.get("text"):
                            chunks.append(item["text"])
                ground = ("\n\n".join(chunks)) or None
                qry = (raw.get("retrieval_queries") or [None])[0] or record.get("name")
                if not ground:
                    log(f"  {record['id']}: no chunk text retained, grounding "
                        f"cannot be evaluated", "warn")
            cases.append((f"{record['id']}_run{record.get('run')}", text, ground, qry))
    elif args.text:
        cases.append(("adhoc", args.text, None, None))
    else:
        suite = yaml.safe_load(SUITE_PATH.read_text(encoding="utf-8"))
        wanted = {i.strip().upper() for i in args.ids.split(",")} if args.ids else None
        for test in suite["tests"]:
            if wanted is not None:
                if test["id"].upper() not in wanted:
                    continue
            elif test["expect"] != "answered":
                continue
            prompt = test.get("prompt") or (test.get("multi_turn") or [""])[-1]
            cases.append((test["id"], prompt, None, None))
    if not cases:
        die("nothing to probe")

    log(f"probing guardrail {state['guardrail_id']} v{version} ({args.source})", "step")
    report = []
    for label, text, ground, qry in cases:
        result = probe(runtime, state["guardrail_id"], version, text, args.source,
                       grounding_source=ground, query=qry)
        if result.get("error"):
            log(f"  {label}: {result['error']}", "err")
            report.append({"id": label, "error": result["error"]})
            continue
        action = result.get("action")
        reasons = explain(result)
        level = "warn" if action and action != "NONE" else "ok"
        log(f"  {label}: action={action} {('- ' + result.get('actionReason')) if result.get('actionReason') else ''}", level)
        for reason in reasons:
            log(f"      {reason}", "warn")
        if not reasons and action not in (None, "NONE"):
            log("      (intervened but no policy detail returned)", "warn")
        report.append({"id": label, "text": text,
                       "grounded": bool(ground), "query": qry, "action": action,
                       "actionReason": result.get("actionReason"),
                       "reasons": reasons, "raw": result})

    write_evidence(f"guardrail_probe_{args.source.lower()}.json",
                   {"guardrail_id": state["guardrail_id"], "version": version,
                    "source": args.source, "cases": report})
    blocked = [r for r in report if r.get("action") not in (None, "NONE")]
    log(f"{len(blocked)} of {len(report)} probed texts triggered the guardrail",
        "warn" if blocked else "ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
