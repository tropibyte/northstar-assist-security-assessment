"""Shared plumbing for the Northstar Assist security scripts.

Design rules that the rest of the scripts rely on:

* Credentials are never read from, or written to, this repository. They come
  from the environment or an AWS profile. Cloud Lab credentials are temporary
  session credentials, so every script re-checks them and fails loudly rather
  than half-running.
* Nothing is hard-coded to one account. Resource identifiers are discovered at
  run time and cached in evidence/state.json, which is the single source of
  truth that later scripts and the written deliverables both read.
* Every AWS call that produces evidence writes its raw response to
  evidence/ as JSON. The deliverables quote those files, so the report is
  traceable back to an actual API response rather than a screenshot memory.
* Account IDs are redactable on the way into documents via redact().
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError

SUBMISSION = Path(__file__).resolve().parents[1]
REPO = SUBMISSION.parent
EVIDENCE = SUBMISSION / "evidence"
STATE_PATH = EVIDENCE / "state.json"
CONFIG_PATH = SUBMISSION / "config.json"
CONFIG_EXAMPLE = SUBMISSION / "config.example.json"

# Retries matter here: AgentCore control-plane calls throttle readily, and a
# throttle in the middle of a metered lab session is expensive to redo.
BOTO_CONFIG = Config(retries={"max_attempts": 8, "mode": "adaptive"})


# --------------------------------------------------------------- logging ---
_LEVEL_PREFIX = {"info": "  ", "ok": "OK", "warn": "!!", "err": "XX", "step": "==>"}


def log(message: str, level: str = "info") -> None:
    stamp = _dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{stamp}] {_LEVEL_PREFIX.get(level, '  ')} {message}", flush=True)


def die(message: str, code: int = 1) -> "None":
    log(message, "err")
    sys.exit(code)


# ---------------------------------------------------------------- config ---
DEFAULT_CONFIG: dict[str, Any] = {
    "region": "us-east-1",
    "bucket": "",
    "kb_name": "northstar-assist-kb",
    "data_source_name": "northstar-documents",
    "gateway_name": "northstar-assist-gateway",
    "gateway_target_name": "northstar-kb",
    "harness_name": "NorthstarAssist",
    "guardrail_name": "northstar-assist-guardrail",
    "model_id": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "embedding_model_id": "amazon.titan-embed-text-v2:0",
    "log_group": "/northstar-assist/model-invocations",
    "alarm_sns_topic_arn": "",
}


def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    env_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if env_region:
        cfg["region"] = env_region
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ----------------------------------------------------------------- state ---
def load_state() -> dict[str, Any]:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {}


def save_state(state: dict[str, Any]) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    state["_updated"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    STATE_PATH.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def update_state(**kwargs: Any) -> dict[str, Any]:
    state = load_state()
    state.update({k: v for k, v in kwargs.items() if v is not None})
    save_state(state)
    return state


def need(state: dict[str, Any], *keys: str) -> None:
    """Fail early with a useful message instead of a KeyError mid-run."""
    missing = [k for k in keys if not state.get(k)]
    if missing:
        die(f"state.json is missing {', '.join(missing)} - run 10_discover.py first")


# -------------------------------------------------------------- evidence ---
def write_evidence(name: str, payload: Any, subdir: str = "") -> Path:
    target = EVIDENCE / subdir if subdir else EVIDENCE
    target.mkdir(parents=True, exist_ok=True)
    path = target / (name if name.endswith(".json") else f"{name}.json")
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    log(f"evidence -> {path.relative_to(REPO)}")
    return path


def redact(text: str, state: dict[str, Any] | None = None) -> str:
    """Replace the account ID with a placeholder for anything published."""
    state = state if state is not None else load_state()
    account = state.get("account_id")
    if account:
        text = text.replace(str(account), "<account-id>")
    return text


# ------------------------------------------------------------------- aws ---
def session(cfg: dict[str, Any] | None = None) -> boto3.session.Session:
    cfg = cfg or load_config()
    profile = os.environ.get("AWS_PROFILE")
    kwargs: dict[str, Any] = {"region_name": cfg["region"]}
    if profile:
        kwargs["profile_name"] = profile
    return boto3.session.Session(**kwargs)


def client(service: str, cfg: dict[str, Any] | None = None,
           sess: boto3.session.Session | None = None):
    sess = sess or session(cfg)
    return sess.client(service, config=BOTO_CONFIG)


def whoami(sess: boto3.session.Session | None = None) -> dict[str, str]:
    """Confirm credentials work and return the caller identity.

    Cloud Lab credentials expire mid-session; catching that here turns a
    confusing failure deep in a build into one clear message.
    """
    sess = sess or session()
    try:
        ident = sess.client("sts", config=BOTO_CONFIG).get_caller_identity()
    except (NoCredentialsError, TokenRetrievalError):
        die("no AWS credentials found - set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY "
            "and AWS_SESSION_TOKEN from the Udacity Cloud Resources tab")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"ExpiredToken", "InvalidClientTokenId", "RequestExpired"}:
            die("AWS credentials have expired - relaunch the Cloud Lab and re-export them")
        die(f"STS call failed: {exc}")
    return {"account_id": ident["Account"], "arn": ident["Arn"], "user_id": ident["UserId"]}


def arn_parts(arn: str) -> dict[str, str]:
    bits = arn.split(":", 5)
    return {
        "partition": bits[1] if len(bits) > 1 else "",
        "service": bits[2] if len(bits) > 2 else "",
        "region": bits[3] if len(bits) > 3 else "",
        "account": bits[4] if len(bits) > 4 else "",
        "resource": bits[5] if len(bits) > 5 else "",
    }


def role_name_from_arn(arn: str) -> str:
    """AmazonBedrockAgentCoreHarness... from arn:aws:iam::123:role/service-role/Name."""
    return arn.rsplit("/", 1)[-1]


def confirm(prompt: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        die(f"{prompt} - refusing to proceed without a terminal; pass --yes if intended")
    return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}


__all__ = [
    "SUBMISSION", "REPO", "EVIDENCE", "STATE_PATH", "CONFIG_PATH", "CONFIG_EXAMPLE",
    "DEFAULT_CONFIG", "log", "die", "load_config", "save_config", "load_state",
    "save_state", "update_state", "need", "write_evidence", "redact", "session",
    "client", "whoami", "arn_parts", "role_name_from_arn", "confirm",
]
