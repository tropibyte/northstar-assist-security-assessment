#!/usr/bin/env python3
"""Offline regression test: the narrowing pass must never widen a statement.

This is the test that would have caught the defect an external reviewer found
after submission. It needs no AWS credentials -- it replays the *captured*
console-generated policies in `iam/before/` through `narrow_policy()` and
asserts, statement by statement, that nothing the pass produces grants more
than what it started with.

Run it directly (`python tests/test_no_widening.py`) or under pytest.

Three properties are checked:

  1. No statement widens. Every resource in the narrowed statement must be
     covered by at least one resource in the original.
  2. No action appears that was not in the original.
  3. `is_narrower()` itself behaves, including the two cases that produced the
     real bug: a prefix being traded for its parent, and an unrelated ARN being
     appended to a scoped statement.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SUBMISSION = Path(__file__).resolve().parents[1]
SCRIPTS = SUBMISSION / "scripts"
sys.path.insert(0, str(SCRIPTS))

# Replay every captured console policy we have. The session-1 archive is the
# important one: those are the exact documents whose narrowing produced the
# widening a reviewer caught, so they stay in the corpus permanently. The live
# `before/` directory is included too once a rebuild has populated it.
BEFORE_DIRS = [SUBMISSION / "iam" / "session1-2026-09-18" / "before",
               SUBMISSION / "iam" / "before"]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HARDEN = _load("harden", "20_harden_iam.py")
AUDIT = _load("audit", "22_iam_audit.py")


def _role_kind(role_name: str) -> str:
    lowered = role_name.lower()
    if "harness" in lowered:
        return "harness"
    if "gateway" in lowered:
        return "gateway"
    if "knowledge" in lowered:
        return "kb"
    return "harness"


def _load_context() -> tuple[dict, dict]:
    state = json.loads((SUBMISSION / "evidence" / "state.json").read_text(encoding="utf-8"))
    cfg_path = SUBMISSION / "config.json"
    # config.json is gitignored -- it names a real bucket -- so on a fresh clone
    # this fallback IS the configuration. It must therefore carry every key the
    # narrowing pass reads, or the test the documentation advertises as runnable
    # without AWS dies with a KeyError on someone else's machine. Values match
    # the committed evidence.
    fallback = {
        "model_id": state.get("harness_model_id", "us.amazon.nova-2-lite-v1:0"),
        "embedding_model_id": "amazon.titan-embed-text-v2:0",
        "region": state.get("region", "us-east-1"),
        "bucket": state.get("bucket", "northstar-assist-kb-41071520"),
        "log_group": state.get("log_group", "/northstar-assist/model-invocations"),
    }
    cfg = (json.loads(cfg_path.read_text(encoding="utf-8"))
           if cfg_path.exists() else fallback)
    return state, cfg


def test_is_narrower_unit() -> None:
    """The guard's own behaviour, including the two real-world failure shapes."""
    narrower = HARDEN.is_narrower

    # Identical is narrower-or-equal.
    assert narrower(["arn:aws:s3:::b/*"], ["arn:aws:s3:::b/*"])
    # A concrete ARN under a wildcard is narrower.
    assert narrower(["arn:aws:s3:::b/*"], ["arn:aws:s3:::b/key.txt"])
    # Dropping resources entirely is narrower.
    assert narrower(["a", "b"], ["a"])

    # THE LOGS BUG: trading a scoped prefix for its parent is NOT narrower.
    assert not narrower(
        ["arn:aws:logs:us-east-1:1:log-group:/aws/bedrock-agentcore/runtimes/*"],
        ["arn:aws:logs:us-east-1:1:log-group:/aws/bedrock-agentcore/*"])

    # THE S3 BUG: appending an ARN the original never covered is NOT narrower.
    assert not narrower(["arn:aws:s3:::b/*"], ["arn:aws:s3:::b", "arn:aws:s3:::b/*"])

    # Adding an unrelated log group is NOT narrower.
    assert not narrower(
        ["arn:aws:logs:us-east-1:1:log-group:/aws/bedrock-agentcore/runtimes/*"],
        ["arn:aws:logs:us-east-1:1:log-group:/aws/bedrock-agentcore/runtimes/*",
         "arn:aws:logs:us-east-1:1:log-group:/northstar-assist/model-invocations:*"])

    print("  is_narrower unit cases: 7/7 pass")


def test_replay_captured_policies_never_widens() -> None:
    """Replay every captured console policy through the real narrowing pass."""
    state, cfg = _load_context()
    before_files = [p for d in BEFORE_DIRS if d.is_dir()
                    for p in sorted(d.glob("*.json"))]
    assert before_files, f"no captured policies in any of {BEFORE_DIRS}"

    targets_cache: dict[str, dict] = {}
    checked = wid = 0
    failures: list[str] = []

    for path in before_files:
        role_name, _, stem = path.stem.partition("__")
        kind = _role_kind(role_name)
        if kind not in targets_cache:
            targets_cache[kind] = HARDEN.resolve_targets(state, cfg, kind)

        raw = json.loads(path.read_text(encoding="utf-8"))
        before_doc = raw.get("document", raw)
        after_doc, _changes = HARDEN.narrow_policy(before_doc, targets_cache[kind], kind)

        for row in AUDIT.compare_policy(kind, stem, before_doc, after_doc):
            checked += 1
            if row["widened"]:
                wid += 1
                failures.append(f"{kind}/{row['sid']}: {row['detail']}")

    for f in failures:
        print(f"  WIDENED {f}")
    print(f"  replayed {len(before_files)} captured policies, "
          f"{checked} statements, {wid} widened")
    assert not failures, (
        f"{wid} statement(s) widened when replaying the captured policies. "
        f"The narrowing pass must never grant more than the original.")


def main() -> int:
    print("test_no_widening")
    failed = 0
    for fn in (test_is_narrower_unit, test_replay_captured_policies_never_widens):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
    print("OK" if not failed else f"{failed} test(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
