"""Delete every resource this project created, in dependency order.

The Cloud Lab budget is fixed and non-renewable, and a forgotten resource is
the usual way it disappears. This script exists so teardown is one command
rather than a checklist executed from memory at the end of a long session.

Order matters: the harness references the gateway, the gateway target
references the knowledge base, and the knowledge base references the bucket.
Deleting bottom-up leaves dangling references that block deletion.

  harness -> gateway targets -> gateway -> data source -> knowledge base
          -> guardrail -> S3 objects -> S3 bucket -> log groups / alarms
          -> model invocation logging -> the inline IAM policy we added

Everything is best-effort and independent: one failure does not abort the rest,
because a half-torn-down account still costs money. --verify at the end lists
anything still standing.

Usage:
  python 99_teardown.py --dry-run     # show what would be deleted
  python 99_teardown.py --yes         # delete everything
  python 99_teardown.py --verify      # list what remains
  python 99_teardown.py --yes --keep-bucket
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botocore.exceptions import ClientError

from ns_common import (client, confirm, load_config, load_state, log,
                       role_name_from_arn, save_state, write_evidence)

APPLY_POLICY_NAME = "NorthstarAssistApplyGuardrail"


class Teardown:
    def __init__(self, cfg, state, dry_run: bool):
        self.cfg, self.state, self.dry = cfg, state, dry_run
        self.done: list[str] = []
        self.failed: list[dict] = []
        self.skipped: list[str] = []

    def _do(self, label: str, fn):
        if self.dry:
            log(f"[dry-run] would delete {label}")
            self.skipped.append(label)
            return
        try:
            fn()
            log(f"deleted {label}", "ok")
            self.done.append(label)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ResourceNotFoundException", "NoSuchBucket", "NoSuchEntity",
                        "ValidationException", "ResourceNotFound", "NotFoundException"}:
                log(f"{label} already gone")
                self.skipped.append(label)
            else:
                log(f"FAILED to delete {label}: {code} {exc}", "err")
                self.failed.append({"resource": label, "error": str(exc)})
        except Exception as exc:
            log(f"FAILED to delete {label}: {exc}", "err")
            self.failed.append({"resource": label, "error": str(exc)})

    # ------------------------------------------------------------- agent ---
    def harness(self):
        hid = self.state.get("harness_id")
        if not hid:
            return
        ctl = client("bedrock-agentcore-control", self.cfg)
        self._do(f"harness {hid}",
                 lambda: ctl.delete_harness(harnessId=hid, deleteManagedMemory=True))
        # The gateway cannot be deleted while a harness still references it.
        if not self.dry:
            time.sleep(5)

    def gateway(self):
        gid = self.state.get("gateway_id")
        if not gid:
            return
        ctl = client("bedrock-agentcore-control", self.cfg)
        try:
            targets = ctl.list_gateway_targets(gatewayIdentifier=gid,
                                               maxResults=50).get("items", [])
        except ClientError:
            targets = []
        for target in targets:
            tid = target["targetId"]
            self._do(f"gateway target {tid}",
                     lambda t=tid: ctl.delete_gateway_target(gatewayIdentifier=gid, targetId=t))
        if targets and not self.dry:
            time.sleep(3)
        self._do(f"gateway {gid}", lambda: ctl.delete_gateway(gatewayIdentifier=gid))

    def knowledge_base(self):
        kb_id = self.state.get("kb_id")
        if not kb_id:
            return
        agent = client("bedrock-agent", self.cfg)
        ds_id = self.state.get("data_source_id")
        if ds_id:
            self._do(f"data source {ds_id}",
                     lambda: agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id))
            if not self.dry:
                time.sleep(3)
        self._do(f"knowledge base {kb_id}",
                 lambda: agent.delete_knowledge_base(knowledgeBaseId=kb_id))

    def guardrail(self):
        gid = self.state.get("guardrail_id")
        if not gid:
            return
        bedrock = client("bedrock", self.cfg)
        # Deleting the guardrail without a version deletes it and all versions.
        self._do(f"guardrail {gid}", lambda: bedrock.delete_guardrail(guardrailIdentifier=gid))

    # ------------------------------------------------------------ storage ---
    def bucket(self, keep: bool):
        name = self.state.get("bucket")
        if not name:
            return
        if keep:
            log(f"keeping bucket {name} (--keep-bucket)")
            self.skipped.append(f"bucket {name}")
            return
        s3 = client("s3", self.cfg)

        def empty_and_delete():
            paginator = s3.get_paginator("list_object_versions")
            deleted = 0
            for page in paginator.paginate(Bucket=name):
                objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objects:
                    s3.delete_objects(Bucket=name, Delete={"Objects": objects})
                    deleted += len(objects)
            # Non-versioned buckets return nothing above; sweep plain keys too.
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=name):
                objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objects:
                    s3.delete_objects(Bucket=name, Delete={"Objects": objects})
                    deleted += len(objects)
            log(f"  emptied {deleted} object(s) from {name}")
            s3.delete_bucket(Bucket=name)

        self._do(f"bucket {name}", empty_and_delete)

    # --------------------------------------------------------- monitoring ---
    def monitoring(self):
        logs = client("logs", self.cfg)
        cw = client("cloudwatch", self.cfg)
        cfg_group = self.cfg.get("log_group")

        prefixes = [p for p in (cfg_group, "/aws/bedrock-agentcore/runtimes/harness_",
                                "/aws/vendedlogs/bedrock/knowledge-base/") if p]
        groups: list[str] = []
        for prefix in prefixes:
            try:
                for page in logs.get_paginator("describe_log_groups").paginate(
                        logGroupNamePrefix=prefix):
                    groups.extend(g["logGroupName"] for g in page.get("logGroups", []))
            except ClientError as exc:
                log(f"could not enumerate log groups for {prefix}: {exc}", "warn")
        for group in sorted(set(groups)):
            self._do(f"log group {group}", lambda g=group: logs.delete_log_group(logGroupName=g))

        # Sweep by prefix rather than by the state list: alarms created during
        # an earlier iteration may no longer be in state (the ZeroChunkRetrieval
        # signal was withdrawn once the logs showed it was not derivable), and
        # an alarm nobody remembers is exactly what gets left behind.
        alarms = set(self.state.get("alarms") or [])
        try:
            for page in cw.get_paginator("describe_alarms").paginate(
                    AlarmNamePrefix="NorthstarAssist-"):
                alarms.update(a["AlarmName"] for a in page.get("MetricAlarms", []))
                alarms.update(a["AlarmName"] for a in page.get("CompositeAlarms", []))
        except ClientError as exc:
            log(f"could not enumerate alarms by prefix: {exc}", "warn")
        if alarms:
            names = sorted(alarms)
            self._do(f"{len(names)} CloudWatch alarm(s): {', '.join(names)}",
                     lambda: cw.delete_alarms(AlarmNames=names))

        filters = self.state.get("metric_filters") or []
        for item in filters:
            self._do(f"metric filter {item['name']}",
                     lambda i=item: logs.delete_metric_filter(
                         logGroupName=i["log_group"], filterName=i["name"]))

    def invocation_logging(self):
        bedrock = client("bedrock", self.cfg)
        self._do("model invocation logging configuration",
                 bedrock.delete_model_invocation_logging_configuration)

    def inline_policy(self):
        arn = self.state.get("harness_role_arn")
        if not arn:
            return
        role = role_name_from_arn(arn)
        iam = client("iam", self.cfg)
        self._do(f"inline policy {role}/{APPLY_POLICY_NAME}",
                 lambda: iam.delete_role_policy(RoleName=role, PolicyName=APPLY_POLICY_NAME))


def verify(cfg) -> dict:
    """List anything project-shaped still present in the account."""
    log("verifying the account is clean", "step")
    remaining: dict[str, list] = {}

    def safe(label, fn):
        try:
            items = fn()
            if items:
                remaining[label] = items
        except ClientError as exc:
            remaining[label] = [f"<query failed: {exc.response.get('Error', {}).get('Code')}>"]

    safe("s3_buckets", lambda: [b["Name"] for b in client("s3", cfg).list_buckets()["Buckets"]
                                if "northstar" in b["Name"].lower()])
    safe("harnesses", lambda: [h.get("harnessName") for h in
                               client("bedrock-agentcore-control", cfg)
                               .list_harnesses(maxResults=50).get("harnesses", [])])
    safe("gateways", lambda: [g.get("name") for g in
                              client("bedrock-agentcore-control", cfg)
                              .list_gateways(maxResults=50).get("items", [])])
    safe("knowledge_bases", lambda: [k["name"] for k in client("bedrock-agent", cfg)
                                     .list_knowledge_bases(maxResults=50)
                                     .get("knowledgeBaseSummaries", [])])
    safe("guardrails", lambda: [g["name"] for g in client("bedrock", cfg)
                                .list_guardrails(maxResults=50).get("guardrails", [])])
    safe("log_groups", lambda: [g["logGroupName"] for g in client("logs", cfg)
                                .describe_log_groups(limit=50).get("logGroups", [])
                                if "northstar" in g["logGroupName"].lower()
                                or "agentcore" in g["logGroupName"].lower()
                                or "knowledge-base" in g["logGroupName"].lower()])

    try:
        conf = client("bedrock", cfg).get_model_invocation_logging_configuration()
        # The call returns 200 with an EMPTY loggingConfig once logging is
        # disabled, so "it did not throw" does not mean "still enabled" -- a
        # destination has to actually be present. Reporting otherwise sends the
        # operator to the console to turn off something already off, which is
        # how a clean teardown gets mistaken for a dirty one.
        logging_config = conf.get("loggingConfig") or {}
        destinations = [k for k in ("cloudWatchConfig", "s3Config") if logging_config.get(k)]
        if destinations:
            remaining["model_invocation_logging"] = destinations
    except ClientError:
        pass

    if remaining:
        log("resources still present:", "warn")
        for label, items in remaining.items():
            log(f"  {label}: {items}", "warn")
    else:
        log("account is clean - nothing left to bill", "ok")
    return remaining


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify", action="store_true", help="only list what remains")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--keep-bucket", action="store_true",
                    help="keep the document bucket (it costs almost nothing)")
    args = ap.parse_args()

    cfg, state = load_config(), load_state()

    if args.verify:
        remaining = verify(cfg)
        write_evidence("teardown_verify.json", remaining)
        return 0 if not remaining else 2

    planned = [k for k in ("harness_id", "gateway_id", "kb_id", "guardrail_id", "bucket")
               if state.get(k)]
    if not planned:
        # A successful run clears the resource keys from state, so a second
        # pass would early-return and leave behind anything that reappeared
        # after the first pass -- notably the runtime log group, which the
        # terminating harness recreates after it is deleted. Sweep the
        # state-independent artefacts instead of refusing to do anything.
        log("state.json lists no primary resources - sweeping monitoring artefacts", "warn")
        td = Teardown(cfg, state, args.dry_run)
        td.monitoring()
        td.invocation_logging()
        td.inline_policy()
        log(f"swept {len(td.done)}, skipped {len(td.skipped)}, failed {len(td.failed)}",
            "ok" if not td.failed else "warn")
        remaining = verify(cfg)
        write_evidence("teardown_sweep.json",
                       {"deleted": td.done, "skipped": td.skipped,
                        "failed": td.failed, "remaining": remaining})
        return 0 if not remaining else 2

    log(f"will delete: {', '.join(planned)}", "step")
    if not args.dry_run and not confirm(
            "delete every Northstar Assist resource? capture your evidence first.", args.yes):
        log("aborted - nothing deleted", "warn")
        return 1

    td = Teardown(cfg, state, args.dry_run)
    td.harness()
    td.gateway()
    td.knowledge_base()
    td.guardrail()
    td.bucket(args.keep_bucket)
    td.monitoring()
    td.invocation_logging()
    td.inline_policy()

    report = {"deleted": td.done, "skipped": td.skipped, "failed": td.failed}
    write_evidence("teardown.json", report)
    log(f"deleted {len(td.done)}, skipped {len(td.skipped)}, failed {len(td.failed)}",
        "ok" if not td.failed else "warn")

    if not args.dry_run:
        # Keep the evidence, drop the resource pointers.
        for key in ("harness_id", "harness_arn", "gateway_id", "gateway_arn",
                    "gateway_target_id", "kb_id", "kb_arn", "data_source_id",
                    "guardrail_id", "guardrail_arn", "bucket", "alarms", "metric_filters"):
            state.pop(key, None)
        state["torn_down_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state(state)
        time.sleep(5)
        remaining = verify(cfg)
        if remaining:
            log("SOME RESOURCES REMAIN - delete them in the console before closing", "err")
            return 2

    return 0 if not td.failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
