"""One-call health check: does the agent still answer, and still retrieve?

Used by 20_harden_iam.py --verify to decide whether a narrowed IAM policy broke
the system. Kept separate and dependency-light so it can be imported safely
mid-hardening.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_client
from ns_common import client, load_config, load_state, log

SMOKE_PROMPT = "What is Northstar's hybrid work policy? Name the source document."


def smoke_test(prompt: str = SMOKE_PROMPT) -> tuple[bool, str]:
    cfg, state = load_config(), load_state()
    if not state.get("harness_arn"):
        return False, "no harness_arn in state.json"

    runtime = client("bedrock-agentcore", cfg)
    result = harness_client.invoke(
        runtime, state["harness_arn"],
        [{"role": "user", "content": [{"text": prompt}]}],
        harness_client.new_session_id(),
    )

    if result.get("error"):
        return False, f"{result['error'].get('code')}: {result['error'].get('message')}"
    if result["intervention_signal"]["blocked"]:
        return False, "guardrail blocked a benign baseline question (over-blocking)"
    if not result.get("used_retrieval"):
        return False, "answered without calling the knowledge base Retrieve tool"
    if result["retrieved_chunks"] == 0:
        return False, "Retrieve tool ran but returned zero chunks"
    if len(result.get("text") or "") < 40:
        return False, f"suspiciously short answer: {result.get('text')!r}"

    return True, (f"answered in {result.get('wall_ms')}ms using "
                  f"{result['retrieved_chunks']} chunk(s), "
                  f"{result.get('usage', {}).get('totalTokens')} tokens")


if __name__ == "__main__":
    ok, detail = smoke_test()
    log(detail, "ok" if ok else "err")
    raise SystemExit(0 if ok else 1)
