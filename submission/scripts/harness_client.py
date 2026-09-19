"""Thin client over InvokeHarness that returns a structured, analysable turn.

InvokeHarness returns a Converse-style event stream. Everything the security
analysis needs has to be reconstructed from it:

  * the assistant text
  * which tools were called, with what query, and how much came back
  * token usage and latency
  * whether the guardrail intervened

That last one is the awkward case. The harness event stream carries NO
guardrail trace event, so intervention cannot be read directly. It is inferred
from two observable signals: the stopReason, and whether the returned text
matches the guardrail's configured blocked-message strings. That inference is
recorded on every turn as `intervention_signal` so the report can state how
the determination was made rather than implying the API said so.

Conversation history is client-supplied: with Memory disabled the service keeps
no state between calls, so multi-turn is built by sending the accumulated
messages list. This is a security property in its own right -- the client, not
the service, is the authority on what was said earlier in the conversation.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

# Substrings drawn from guardrail/guardrail.json. Kept here as a fallback; the
# runner overrides them with the live values read back from GetGuardrail.
DEFAULT_BLOCKED_MARKERS = (
    "That request can't be processed",
    "The response was withheld",
)

RETRIEVE_TOOL_HINTS = ("retrieve", "knowledge", "northstar-kb", "northstar_kb")


def new_session_id() -> str:
    """AgentCore requires 33-100 chars matching [a-zA-Z0-9][a-zA-Z0-9-_]*."""
    return f"ns{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}"[:100]


def _text_content(text: str) -> list[dict]:
    return [{"text": text}]


def invoke(client, harness_arn: str, messages: list[dict], session_id: str,
           blocked_markers: tuple[str, ...] = DEFAULT_BLOCKED_MARKERS,
           timeout_note: str = "") -> dict:
    """Run one turn. Never raises on an AWS error; returns it in the result."""
    started = time.time()
    result: dict[str, Any] = {
        "session_id": session_id,
        "text": "",
        "stop_reason": None,
        "tool_calls": [],
        "usage": {},
        "latency_ms": None,
        "events": 0,
        "error": None,
        "retrieved_chunks": 0,
        "retrieval_queries": [],
    }

    try:
        response = client.invoke_harness(
            harnessArn=harness_arn,
            runtimeSessionId=session_id,
            messages=messages,
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        result["error"] = {"code": err.get("Code"), "message": err.get("Message")}
        result["wall_ms"] = int((time.time() - started) * 1000)
        return result

    # Tool state is assembled across contentBlockStart/Delta/Stop events keyed
    # by contentBlockIndex, because deltas arrive interleaved.
    open_blocks: dict[int, dict] = {}

    try:
        for event in response["stream"]:
            result["events"] += 1

            for exc_key in ("internalServerException", "validationException",
                            "runtimeClientError"):
                if exc_key in event:
                    result["error"] = {"code": exc_key,
                                       "message": event[exc_key].get("message")}

            if "contentBlockStart" in event:
                block = event["contentBlockStart"]
                index = block.get("contentBlockIndex", 0)
                start = block.get("start", {})
                if "toolUse" in start:
                    open_blocks[index] = {
                        "kind": "toolUse",
                        "name": start["toolUse"].get("name"),
                        "server": start["toolUse"].get("serverName"),
                        "input": "",
                    }
                elif "toolResult" in start:
                    open_blocks[index] = {
                        "kind": "toolResult",
                        "status": start["toolResult"].get("status"),
                        "payload": [],
                    }

            if "contentBlockDelta" in event:
                block = event["contentBlockDelta"]
                index = block.get("contentBlockIndex", 0)
                delta = block.get("delta", {})
                if "text" in delta:
                    result["text"] += delta["text"]
                if "toolUse" in delta and index in open_blocks:
                    open_blocks[index]["input"] += delta["toolUse"].get("input", "")
                if "toolResult" in delta and index in open_blocks:
                    open_blocks[index].setdefault("payload", []).extend(delta["toolResult"])

            if "contentBlockStop" in event:
                index = event["contentBlockStop"].get("contentBlockIndex", 0)
                block = open_blocks.pop(index, None)
                if block:
                    result["tool_calls"].append(_finalise_block(block, result))

            if "messageStop" in event:
                result["stop_reason"] = event["messageStop"].get("stopReason")

            if "metadata" in event:
                meta = event["metadata"]
                result["usage"] = meta.get("usage", {}) or {}
                result["latency_ms"] = (meta.get("metrics") or {}).get("latencyMs")
    except Exception as exc:  # stream interruption is itself a result
        result["error"] = {"code": "StreamError", "message": str(exc)}

    for block in open_blocks.values():  # stream ended mid-block
        result["tool_calls"].append(_finalise_block(block, result))

    result["wall_ms"] = int((time.time() - started) * 1000)
    result["used_retrieval"] = any(
        c.get("kind") == "toolUse" and _is_retrieve(c.get("name"), c.get("server"))
        for c in result["tool_calls"])
    result["intervention_signal"] = _intervention_signal(result, blocked_markers)
    if timeout_note:
        result["note"] = timeout_note
    return result


def _is_retrieve(name: str | None, server: str | None) -> bool:
    blob = f"{name or ''} {server or ''}".lower()
    return any(hint in blob for hint in RETRIEVE_TOOL_HINTS)


def _finalise_block(block: dict, result: dict) -> dict:
    if block["kind"] == "toolUse":
        raw = block.get("input") or ""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"_unparsed": raw}
        block["parsed_input"] = parsed
        query = parsed.get("retrievalQuery") or parsed.get("query") or parsed.get("text")
        if isinstance(query, dict):
            query = query.get("text")
        if query and _is_retrieve(block.get("name"), block.get("server")):
            result["retrieval_queries"].append(query)
    elif block["kind"] == "toolResult":
        chunks = 0
        for item in block.get("payload", []):
            payload = item.get("json") if isinstance(item, dict) else None
            if isinstance(payload, dict):
                results = payload.get("retrievalResults") or payload.get("content") or []
                if isinstance(results, list):
                    chunks += len(results)
            elif isinstance(item, dict) and item.get("text"):
                chunks += 1
        block["chunk_count"] = chunks
        result["retrieved_chunks"] += chunks
        # Retain the retrieved text, not just a sample of it. This is what lets
        # a contextual-grounding block be reproduced afterwards with
        # ApplyGuardrail: the grounding filter compares the answer against the
        # source, so a truncated source under-reports the grounding score and
        # makes the replay look more suspicious than the real call was.
        block["payload"] = block.get("payload", [])[:20]
    return block


def _intervention_signal(result: dict, markers: tuple[str, ...]) -> dict:
    """Best-effort determination of whether the guardrail blocked this turn."""
    text = (result.get("text") or "").strip()
    stop = (result.get("stop_reason") or "").lower()
    matched = next((m for m in markers if m and m.lower() in text.lower()), None)
    by_stop = "guardrail" in stop
    return {
        "blocked": bool(matched) or by_stop,
        "matched_blocked_message": matched,
        "stop_reason_indicates_guardrail": by_stop,
        "method": "blocked-message fingerprint + stopReason "
                  "(the harness stream exposes no guardrail trace event)",
    }


def run_conversation(client, harness_arn: str, turns: list[str],
                     blocked_markers: tuple[str, ...] = DEFAULT_BLOCKED_MARKERS,
                     session_id: str | None = None) -> dict:
    """Multi-turn. History is accumulated client-side and resent each turn."""
    session_id = session_id or new_session_id()
    messages: list[dict] = []
    turn_results = []
    for turn in turns:
        messages.append({"role": "user", "content": _text_content(turn)})
        outcome = invoke(client, harness_arn, messages, session_id, blocked_markers)
        turn_results.append({"prompt": turn, **outcome})
        if outcome.get("error"):
            break
        messages.append({"role": "assistant",
                         "content": _text_content(outcome.get("text") or "")})
    return {
        "session_id": session_id,
        "turns": turn_results,
        "final": turn_results[-1] if turn_results else None,
        "message_count": len(messages),
    }
