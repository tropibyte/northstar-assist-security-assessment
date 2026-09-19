"""Re-score saved transcripts with the current classifier. No AWS calls.

Every run writes its full raw response to evidence/transcripts/<mode>/. That
means scoring is a pure function of evidence already captured, so when the
classifier is corrected the existing results can be rebuilt instead of
re-running the suite against a metered lab account.

This matters for more than convenience. The first baseline run scored PI-06 as
ERROR because hitting the token cap surfaces as a stream error -- when what
actually happened was a successful extraction of the employee directory that
ran out of room. Re-scoring turns that back into the FAIL it always was,
without pretending the original run said something it did not: the transcript
is unchanged and the rebuild is reproducible from it.

Usage:
  python 45_rescore.py --mode baseline
  python 45_rescore.py --mode hardened
  python 45_rescore.py --all
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import importlib.util

from ns_common import SUBMISSION, die, load_state, log, write_evidence

# 40_run_tests.py is not importable by name (leading digit), so load it by path
# and reuse its classifier rather than duplicating the scoring logic here.
_spec = importlib.util.spec_from_file_location(
    "run_tests", Path(__file__).resolve().parent / "40_run_tests.py")
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)


def rescore_mode(mode: str, state: dict) -> dict | None:
    folder = SUBMISSION / "evidence" / "transcripts" / mode
    if not folder.is_dir():
        log(f"no transcripts for mode '{mode}'", "warn")
        return None

    suite = runner.load_suite()
    tests_by_id = {t["id"]: t for t in suite["tests"]}

    rows, changed = [], []
    for path in sorted(folder.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        raw = record.get("raw")
        if not raw:
            log(f"  {path.name}: no raw payload, skipping", "warn")
            continue

        test = tests_by_id.get(record["id"])
        if not test:
            log(f"  {path.name}: id {record['id']} not in the suite, skipping", "warn")
            continue

        c = runner.classify(raw, test)
        v = runner.verdict(test["expect"], c)

        old_outcome = (record.get("classification") or {}).get("outcome")
        old_verdict = record.get("verdict")
        if old_outcome != c["outcome"] or old_verdict != v:
            changed.append({
                "id": record["id"], "run": record.get("run"),
                "from": f"{old_outcome}/{old_verdict}", "to": f"{c['outcome']}/{v}",
            })

        row = dict(record)
        row["classification"] = c
        row["verdict"] = v
        row["rescored"] = True
        row.pop("raw", None)
        rows.append(row)

        record["classification"] = c
        record["verdict"] = v
        record["rescored_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    if not rows:
        return None

    summary = runner.summarise(rows, suite)
    payload = {
        "mode": mode, "suite": suite["suite"],
        "rescored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": f"evidence/transcripts/{mode}/",
        "harness_arn": state.get("harness_arn"),
        "reclassified": changed,
        "summary": summary, "rows": rows,
    }
    write_evidence(f"test_results_{mode}.json", payload)
    out_md = SUBMISSION / "docs" / f"test-results-{mode}.md"
    out_md.write_text(runner.render_markdown(rows, summary, mode, state), encoding="utf-8")

    log(f"{mode}: {len(rows)} run(s) re-scored -> {out_md.relative_to(SUBMISSION)}", "ok")
    if changed:
        log(f"  {len(changed)} verdict(s) changed:", "warn")
        for item in changed:
            log(f"    {item['id']} run{item['run']}: {item['from']} -> {item['to']}", "warn")
    else:
        log("  no verdicts changed")
    log(f"  verdicts: {summary['verdicts']}")
    log(f"  block rate on attacks: {summary['block_rate_on_attacks']}")
    log(f"  over-block rate on benign: {summary['over_block_rate_on_benign']}")
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["baseline", "hardened"])
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    if not args.mode and not args.all:
        ap.error("pass --mode baseline|hardened or --all")

    state = load_state()
    modes = ["baseline", "hardened"] if args.all else [args.mode]
    any_done = False
    for mode in modes:
        if rescore_mode(mode, state):
            any_done = True
    if not any_done:
        die("nothing re-scored - no transcripts found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
