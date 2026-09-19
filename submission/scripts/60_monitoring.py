"""Stand up the monitoring described in the Task 6 plan.

Creates, in order:
  1. a CloudWatch log group for Bedrock model invocation logs
  2. an IAM role Bedrock can assume to write to it
  3. model invocation logging, pointed at that group, with trace data enabled
  4. metric filters that turn log content into countable AI-specific signals
  5. CloudWatch alarms on those metrics

Honesty note on the metric filters: the precise JSON shape of a guardrail
intervention inside a Bedrock invocation log record is not something to assert
from documentation alone. --discover samples real log events and prints their
structure so the filter patterns can be confirmed against reality before the
alarms are trusted. Run the test suite first, then --discover, then --filters.

Usage:
  python 60_monitoring.py --enable-logging
  python 60_monitoring.py --discover          # inspect real log records
  python 60_monitoring.py --filters --alarms
  python 60_monitoring.py --status
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (SUBMISSION, client, load_config, load_state, log,
                       update_state, write_evidence)

LOGGING_ROLE = "NorthstarAssistBedrockLoggingRole"
METRIC_NAMESPACE = "NorthstarAssist/Security"

# Each signal: a metric filter that counts an AI-specific event, plus the alarm
# threshold justified in the monitoring plan. Patterns are CloudWatch Logs
# filter syntax over the Bedrock invocation log JSON.
# Patterns are written against the log structure observed in THIS account via
# --discover, not against documentation. Three corrections came out of that:
#
#   * the trace lives at $.output.outputBodyJson.trace.guardrail, not under an
#     "amazon-bedrock-trace" key;
#   * assessments are keyed by guardrail ID, so {gid} is templated in rather
#     than wildcarded -- CloudWatch allows only ONE wildcard per JSON selector
#     and "inputAssessment.*.contentPolicy.filters[*]" used two, which is why
#     the first prompt-attack filter was rejected outright;
#   * $.output.outputBodyJson.stopReason carries "guardrail_intervened", which
#     is a simpler and more reliable intervention signal than any assessment
#     field.
#
# `verified` records whether the pattern's fields were seen in a real record.
SIGNALS = [
    {
        "name": "GuardrailIntervention",
        "metric": "GuardrailInterventions",
        "pattern": '{ $.output.outputBodyJson.stopReason = "guardrail_intervened" }',
        "verified": "stopReason observed in live records",
        "description": "Any guardrail intervention, input or output side.",
        "alarm": {
            "threshold": 10, "period": 3600, "evaluation_periods": 1,
            "rationale": "A handful of interventions per hour is normal for an internal "
                         "assistant. Ten in one hour from a population this size means "
                         "either a probing user or a broken prompt template.",
        },
    },
    {
        "name": "PromptAttackDetected",
        "metric": "PromptAttackInterventions",
        "pattern": '{{ $.output.outputBodyJson.trace.guardrail.inputAssessment.{gid}.'
                   'contentPolicy.filters[*].type = "PROMPT_ATTACK" }}',
        "verified": "path structure observed; guardrail ID templated to stay within "
                    "the one-wildcard limit",
        "description": "Interventions attributed specifically to the prompt attack filter.",
        "alarm": {
            "threshold": 5, "period": 3600, "evaluation_periods": 1,
            "rationale": "The headline alert. Five prompt-attack interventions in one "
                         "hour is well above accidental phrasing and indicates deliberate "
                         "probing; it warrants paging the on-call analyst.",
        },
    },
    {
        "name": "GroundingBlocked",
        "metric": "GroundingBlocks",
        "pattern": '{{ $.output.outputBodyJson.trace.guardrail.outputAssessments[0].{gid}.'
                   'contextualGroundingPolicy.filters[*].action = "BLOCKED" }}',
        "verified": "path structure observed on the output assessment",
        "description": "Answers withheld because they could not be grounded in the "
                       "retrieved documents.",
        "alarm": {
            "threshold": 8, "period": 3600, "evaluation_periods": 1,
            "rationale": "This is the only control that caught corpus poisoning in "
                         "testing, and it caught it in 2 of 3 attempts. A rising rate "
                         "means either the corpus has drifted from what users ask about "
                         "or something in the index is contradicting itself - which is "
                         "exactly what a poisoned document looks like from outside.",
        },
    },
    {
        "name": "HighTokenResponse",
        "metric": "HighTokenResponses",
        "pattern": "{ $.output.outputTokenCount > 3000 }",
        "verified": "outputTokenCount observed in live records",
        "description": "Single responses far above the session average, the signature "
                       "of an amplification or bulk-extraction attempt.",
        "alarm": {
            "threshold": 5, "period": 3600, "evaluation_periods": 1,
            "rationale": "Normal policy answers run a few hundred output tokens. "
                         "Repeated multi-thousand-token responses are either a cost "
                         "attack or bulk extraction of corpus content. In testing, the "
                         "token cap was the ONLY thing that stopped a forged-context "
                         "attack mid-way through dumping the employee directory.",
        },
    },
    {
        "name": "ToolCallFailure",
        "metric": "ToolCallFailures",
        "pattern": '{ $.output.outputBodyJson.stopReason = "malformed_tool_use" }',
        "verified": "observed during testing (FP-05 run 2)",
        "description": "The model emitted a tool call the runtime could not parse, so "
                       "retrieval silently did not happen.",
        "alarm": {
            "threshold": 5, "period": 3600, "evaluation_periods": 1,
            "rationale": "A reliability signal with a security consequence: a failed "
                         "tool call produces an answer with no retrieval behind it, "
                         "which is indistinguishable to the user from a grounded one.",
        },
    },
]

# Signals that are NOT derivable from model invocation logs, recorded so the
# monitoring plan states the gap rather than shipping a pattern that looks
# plausible and silently counts nothing.
UNDERIVABLE_SIGNALS = [
    {
        "name": "ZeroChunkRetrieval",
        "why": "Retrieval happens in the AgentCore Gateway, not in the model call. A "
               "ConverseStream record shows the tool CONFIG but not how many chunks came "
               "back, and a single user turn produces several records. Counting "
               "zero-chunk answers requires the harness runtime log group "
               "(/aws/bedrock-agentcore/runtimes/harness_<name>-<id>-DEFAULT) or "
               "client-side instrumentation such as the test harness in "
               "submission/scripts/harness_client.py, which records retrieved_chunks "
               "per turn directly.",
    },
]


def ensure_log_group(cfg) -> str:
    logs = client("logs", cfg)
    name = cfg["log_group"]
    try:
        logs.create_log_group(logGroupName=name)
        log(f"created log group {name}", "ok")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            log(f"log group {name} already exists")
        else:
            raise
    # Retention keeps a forgotten lab account from accruing storage charges.
    logs.put_retention_policy(logGroupName=name, retentionInDays=7)
    log("retention set to 7 days", "ok")
    return name


def ensure_logging_role(cfg, state, log_group: str) -> str:
    iam = client("iam", cfg)
    account, region = state["account_id"], state["region"]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
            # Confused-deputy protection: only this account's Bedrock may assume it.
            "Condition": {
                "StringEquals": {"aws:SourceAccount": account},
                "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{region}:{account}:*"},
            },
        }],
    }
    try:
        role = iam.create_role(RoleName=LOGGING_ROLE,
                               AssumeRolePolicyDocument=json.dumps(trust),
                               Description="Lets Bedrock write model invocation logs")["Role"]
        log(f"created role {LOGGING_ROLE}", "ok")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        role = iam.get_role(RoleName=LOGGING_ROLE)["Role"]
        log(f"role {LOGGING_ROLE} already exists")

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "WriteInvocationLogs",
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{region}:{account}:log-group:{log_group}:log-stream:*",
        }],
    }
    iam.put_role_policy(RoleName=LOGGING_ROLE, PolicyName="WriteInvocationLogs",
                        PolicyDocument=json.dumps(policy))
    (SUBMISSION / "iam" / "after" / f"{LOGGING_ROLE}__WriteInvocationLogs.json").write_text(
        json.dumps(policy, indent=2), encoding="utf-8")
    log("scoped logging policy attached (one log group, write-only)", "ok")
    return role["Arn"]


def enable_logging(cfg, state) -> None:
    log_group = ensure_log_group(cfg)
    role_arn = ensure_logging_role(cfg, state, log_group)
    log("waiting 10s for the new role to propagate", "step")
    time.sleep(10)

    bedrock = client("bedrock", cfg)
    config = {
        "cloudWatchConfig": {"logGroupName": log_group, "roleArn": role_arn},
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    }
    for attempt in range(5):
        try:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=config)
            break
        except ClientError as exc:
            # IAM propagation commonly rejects the first attempt.
            if "cannot assume" in str(exc).lower() or "ValidationException" in str(exc):
                log(f"  attempt {attempt + 1}: role not yet assumable, retrying")
                time.sleep(8)
                continue
            raise
    else:
        log("could not enable invocation logging - enable it in the console", "err")
        return

    log("model invocation logging ENABLED", "ok")
    log("text data delivery is on: prompts and completions are now written to "
        "CloudWatch, which is itself sensitive - note this in the threat model", "warn")
    update_state(log_group=log_group, logging_role_arn=role_arn)
    write_evidence("model_invocation_logging.json",
                   bedrock.get_model_invocation_logging_configuration())


def discover(cfg, state) -> None:
    """Sample real log records so the filter patterns can be verified."""
    logs = client("logs", cfg)
    group = state.get("log_group") or cfg["log_group"]
    log(f"sampling recent records from {group}", "step")
    try:
        streams = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime", descending=True,
            limit=5).get("logStreams", [])
    except ClientError as exc:
        log(f"cannot read {group}: {exc}", "err")
        return
    if not streams:
        log("no log streams yet - run the test suite first, then re-run --discover", "warn")
        return

    samples = []
    for stream in streams:
        events = logs.get_log_events(logGroupName=group,
                                     logStreamName=stream["logStreamName"],
                                     limit=5, startFromHead=False).get("events", [])
        for event in events:
            try:
                samples.append(json.loads(event["message"]))
            except json.JSONDecodeError:
                samples.append({"_raw": event["message"][:2000]})
    if not samples:
        log("streams exist but hold no events yet", "warn")
        return

    write_evidence("invocation_log_samples.json", samples[:10], subdir="logs")

    def paths(obj, prefix="$"):
        out = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                out.extend(paths(v, f"{prefix}.{k}"))
        elif isinstance(obj, list) and obj:
            out.extend(paths(obj[0], f"{prefix}[0]"))
        else:
            out.append(f"{prefix} = {type(obj).__name__}")
        return out

    log(f"{len(samples)} record(s) sampled. Field paths in the newest:", "ok")
    for path in paths(samples[0])[:60]:
        log(f"  {path}")
    guardrail_hits = [p for s in samples for p in paths(s) if "guardrail" in p.lower()]
    if guardrail_hits:
        log("guardrail-related paths present:", "ok")
        for path in sorted(set(guardrail_hits))[:25]:
            log(f"  {path}")
    else:
        log("no guardrail fields in these records - run a blocked prompt, then re-sample", "warn")


def signal_pattern(signal: dict, state: dict) -> str:
    """Fill the guardrail ID into patterns that address an assessment.

    Assessments are keyed by guardrail ID in the log record. Using a literal ID
    instead of a wildcard keeps each selector within CloudWatch's limit of one
    wildcard, and makes the filter fail loudly if pointed at another guardrail
    rather than silently matching nothing.
    """
    if "{gid}" not in signal["pattern"]:
        return signal["pattern"]
    gid = state.get("guardrail_id")
    if not gid:
        raise ValueError(f"{signal['name']} needs guardrail_id in state.json")
    return signal["pattern"].format(gid=gid)


def create_filters(cfg, state) -> None:
    logs = client("logs", cfg)
    group = state.get("log_group") or cfg["log_group"]
    created = []
    for signal in UNDERIVABLE_SIGNALS:
        log(f"not creating {signal['name']}: {signal['why'][:90]}...", "warn")
    for signal in SIGNALS:
        try:
            pattern = signal_pattern(signal, state)
            logs.put_metric_filter(
                logGroupName=group,
                filterName=signal["name"],
                filterPattern=pattern,
                metricTransformations=[{
                    "metricName": signal["metric"],
                    "metricNamespace": METRIC_NAMESPACE,
                    "metricValue": "1",
                    "defaultValue": 0,
                }])
            log(f"metric filter {signal['name']} -> {METRIC_NAMESPACE}/{signal['metric']}", "ok")
            created.append({"name": signal["name"], "log_group": group,
                            "pattern": pattern})
        except ValueError as exc:
            log(f"filter {signal['name']} skipped: {exc}", "warn")
        except ClientError as exc:
            log(f"filter {signal['name']} rejected: {exc}", "err")
            log("  check the pattern against --discover output", "warn")
    update_state(metric_filters=created)


def create_alarms(cfg, state) -> None:
    cw = client("cloudwatch", cfg)
    topic = cfg.get("alarm_sns_topic_arn")
    names = []
    for signal in SIGNALS:
        alarm = signal["alarm"]
        name = f"NorthstarAssist-{signal['name']}"
        kwargs = {
            "AlarmName": name,
            "AlarmDescription": f"{signal['description']} Threshold rationale: {alarm['rationale']}",
            "Namespace": METRIC_NAMESPACE,
            "MetricName": signal["metric"],
            "Statistic": "Sum",
            "Period": alarm["period"],
            "EvaluationPeriods": alarm["evaluation_periods"],
            "Threshold": alarm["threshold"],
            "ComparisonOperator": "GreaterThanThreshold",
            "TreatMissingData": "notBreaching",
        }
        if topic:
            kwargs["AlarmActions"] = [topic]
        cw.put_metric_alarm(**kwargs)
        log(f"alarm {name}: {signal['metric']} > {alarm['threshold']} "
            f"per {alarm['period']}s", "ok")
        names.append(name)
    if not topic:
        log("no alarm_sns_topic_arn in config.json - alarms evaluate but notify nobody", "warn")
    update_state(alarms=names)
    write_evidence("alarms.json", {"namespace": METRIC_NAMESPACE, "alarms": names,
                                   "signals": SIGNALS,
                                   "not_derivable": UNDERIVABLE_SIGNALS,
                                   "resolved_patterns": {
                                       s["name"]: s["pattern"].replace(
                                           "{gid}", state.get("guardrail_id", "?"))
                                       for s in SIGNALS}})


def status(cfg, state) -> None:
    bedrock = client("bedrock", cfg)
    try:
        # Empty loggingConfig means disabled; the call still returns 200, and
        # indexing the key directly raises an uncaught KeyError in that case.
        conf = bedrock.get_model_invocation_logging_configuration().get("loggingConfig") or {}
        cwc = conf.get("cloudWatchConfig") or {}
        if cwc.get("logGroupName"):
            log(f"invocation logging ON -> {cwc['logGroupName']}", "ok")
        else:
            log("invocation logging is OFF", "warn")
    except ClientError:
        log("invocation logging is OFF", "warn")

    cw = client("cloudwatch", cfg)
    alarms = cw.describe_alarms(AlarmNamePrefix="NorthstarAssist-").get("MetricAlarms", [])
    for alarm in alarms:
        log(f"  {alarm['AlarmName']}: {alarm['StateValue']} "
            f"({alarm['MetricName']} > {alarm['Threshold']})")
    if not alarms:
        log("  no alarms present")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--enable-logging", action="store_true")
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--filters", action="store_true")
    ap.add_argument("--alarms", action="store_true")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()
    if not any(vars(args).values()):
        ap.error("choose at least one action")

    cfg, state = load_config(), load_state()
    if args.enable_logging:
        enable_logging(cfg, state)
        state = load_state()
    if args.discover:
        discover(cfg, state)
    if args.filters:
        create_filters(cfg, state)
        state = load_state()
    if args.alarms:
        create_alarms(cfg, state)
    if args.status:
        status(cfg, load_state())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
