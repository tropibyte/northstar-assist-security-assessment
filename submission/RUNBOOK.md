# Cloud Lab Runbook — Northstar Assist

Execute top to bottom. Everything that can be done offline already is; this is
the part that needs a live account.

**Shell: PowerShell 7.** Run the `cd` once per window; every command below
assumes you are already in the project directory. PowerShell reads
`/c/Users/...` as `C:\c\Users\...`, so Windows paths are used throughout.

```powershell
cd "C:\Users\tarie\source\repos\Woolf\cd15147-Foundations-Operational-AI-Security"
```

**Ordering is deliberate.** Invocation logging is switched on *before* any test
runs, so every invocation lands in CloudWatch. The baseline test run happens
*before* the guardrail is attached, so there is a genuine before/after delta.
Teardown is last and is not optional.

Rough cost: the full sequence is ~180 Claude Haiku 4.5 invocations plus a few
cents of storage and embedding. Expect **well under $5** of the $25 budget. The
real risk is leaving resources running, not the calls themselves.

---

## Phase 0 — Before you press *Start Cloud Resource*

**0.1** Create your config from the example and pick a bucket suffix:

```powershell
Copy-Item submission\config.example.json submission\config.json
```

Edit `submission/config.json` and set `bucket` to something globally unique
using **random digits** — e.g. `northstar-assist-kb-48127390`. Udacity forbids
personal information in AWS resource names, so no initials or name.

**0.2** Now press **Start Cloud Resource**, then **Copy** each of the three
credential values and set them in *your* PowerShell window. Do not paste them
into this chat — I never need to see them:

```powershell
$env:AWS_ACCESS_KEY_ID="<paste>"; $env:AWS_SECRET_ACCESS_KEY="<paste>"; $env:AWS_SESSION_TOKEN="<paste>"; $env:AWS_REGION="us-east-1"
```

These are session credentials and they expire. If a script later reports
`ExpiredToken`, re-copy them from the Cloud Resources tab and re-export.

---

## Phase 1 — Preflight (read-only, zero cost)

```powershell
.\.venv\Scripts\python.exe submission\scripts\00_preflight.py
```

Confirms credentials, region, that Claude Haiku 4.5 and Titan Embeddings V2 are
both reachable, and that the account has no leftovers. **Do not continue if this
reports issues** — a missing model here is a region problem, and finding out
after building the knowledge base wastes the session.

---

## Phase 2 — Console creation

Follow the project's Environment Setup steps. Four resources, in this order.

| # | Resource | Name | Screenshot to capture |
|---|---|---|---|
| 2.1 | S3 bucket | from your `config.json` | Upload result showing **30 succeeded, 0 failed** |
| 2.2 | Managed KB | `northstar-assist-kb` | KB detail page: status **Available**, service role, embeddings model `amazon.titan-embed-text-v2:0` |
| 2.3 | Gateway + target | `northstar-assist-gateway` / `northstar-kb` | Target config showing MCP + Connectors + Knowledge Bases (KB) + IAM Role |
| 2.4 | Harness | `NorthstarAssist` | Harness detail: status **Ready**, IAM role, harness ARN |

Settings that matter and are easy to miss:

- KB → Additional configurations → **Bedrock embeddings model**, **Create and use a new service role**
- Gateway → Inbound Auth → **Use IAM permissions**; Outbound → **IAM Role**
- Harness → **Memory OFF**; Tools → **Gateway ON** only (Browser, Code Interpreter, Remote MCP, Custom functions all off)
- Harness → leave **Parameters empty** — the guardrail is attached in Phase 6, by script
- After the KB is Available: select the data source and **Sync**, and wait for it to finish with zero failures

Save all screenshots into `submission/evidence/screenshots/`.

---

## Phase 3 — Capture what the console actually built

```powershell
.\.venv\Scripts\python.exe submission\scripts\10_discover.py
```

Writes `evidence/state.json` plus raw API responses under `evidence/discovery/`.
Everything after this reads `state.json`, so it must succeed.

If it reports the knowledge base was not found, AgentCore Managed KBs are not
listing through `ListKnowledgeBases`. Copy the KB id out of the console URL and
re-run:

```powershell
.\.venv\Scripts\python.exe submission\scripts\10_discover.py --kb-id <KB_ID>
```

Tell me the output of this step — the ML-BOM and the threat model both get
written from it.

---

## Phase 4 — Turn on invocation logging *before* any testing

```powershell
.\.venv\Scripts\python.exe submission\scripts\60_monitoring.py --enable-logging
```

Creates the log group, a scoped delivery role, and switches on model invocation
logging with text delivery. From here every invocation is captured, which is
what Phase 9 mines.

---

## Phase 5 — Task 1 evidence, then the baseline run

**5.1** Smoke test — proves the agent answers *and* retrieves:

```powershell
.\.venv\Scripts\python.exe submission\scripts\40_run_tests.py --smoke
```

**5.2** In the console, open **Harness playground**, ask
`What is Northstar's hybrid work policy? Name the source document.`, expand the
**Agent trace**, click the `Retrieve` tool call, and screenshot the panel showing
the query, the retrieved chunks, the source document and the relevance score.
That screenshot is the Task 1 deliverable.

**5.3** Baseline run with **no guardrail attached** — this is what the system
does before controls:

```powershell
.\.venv\Scripts\python.exe submission\scripts\40_run_tests.py --mode baseline --runs 1 --skip-canary
```

One run per test, canary tests skipped — enough to establish the delta without
spending the budget twice.

---

## Phase 6 — Guardrail (Task 5)

```powershell
.\.venv\Scripts\python.exe submission\scripts\30_guardrail.py --create --attach
```

This creates the guardrail from `guardrail/guardrail.json`, cuts version 1,
grants `bedrock:ApplyGuardrail` scoped to that one guardrail, attaches it as
`guardrailConfig` with `trace: enabled`, and verifies the gateway tool survived
the update. Then confirm:

```powershell
.\.venv\Scripts\python.exe submission\scripts\30_guardrail.py --status
```

Screenshot the guardrail's console page (filters, denied topics, PII) for the
Task 5 write-up.

---

## Phase 7 — IAM least privilege (Task 4)

Run these in order. The guardrail must already exist so `ApplyGuardrail` can be
scoped to a real ARN.

```powershell
.\.venv\Scripts\python.exe submission\scripts\20_harden_iam.py --dump
```

```powershell
.\.venv\Scripts\python.exe submission\scripts\20_harden_iam.py --plan
```

Read the plan output. It prints every statement it will narrow, split, remove or
leave alone. Then apply, with automatic rollback if the agent stops working:

```powershell
.\.venv\Scripts\python.exe submission\scripts\20_harden_iam.py --apply --verify
```

If it rolls back, that is a result worth keeping — send me the output and we
document which permission turned out to be load-bearing.

---

## Phase 8 — Canary, then the full hardened run (Task 7)

**8.1** Plant the indirect-injection canary:

```powershell
.\.venv\Scripts\python.exe submission\scripts\35_canary.py --plant
```

**8.2** Full suite against the hardened system — 29 tests, ~78 invocations,
roughly 10–15 minutes:

```powershell
.\.venv\Scripts\python.exe submission\scripts\40_run_tests.py --mode hardened
```

**8.3** Remove the canary immediately afterwards:

```powershell
.\.venv\Scripts\python.exe submission\scripts\35_canary.py --remove
```

**8.4** Screenshot two playground exchanges for the write-up: one blocked prompt
injection and one blocked denied topic, both showing your guardrail's blocked
message.

---

## Phase 9 — Monitoring signals and alarms (Task 6)

Now that real traffic exists, confirm what the logs actually contain before
trusting any filter pattern:

```powershell
.\.venv\Scripts\python.exe submission\scripts\60_monitoring.py --discover
```

Send me that output. It prints the real JSON field paths from your invocation
log records, including any guardrail fields. I will correct the metric filter
patterns against it rather than trusting documentation. Then:

```powershell
.\.venv\Scripts\python.exe submission\scripts\60_monitoring.py --filters --alarms --status
```

Screenshot the CloudWatch alarms list and the log groups list.

---

## Phase 10 — Evidence sweep, then tear down

**10.1** Confirm you have everything. Once the resources are gone, a missing
screenshot means rebuilding:

- [ ] 30/0 S3 upload result
- [ ] KB Available + service role + embeddings model
- [ ] KB data source sync complete, zero failures
- [ ] Gateway target configuration
- [ ] Harness Ready + role + ARN
- [ ] Playground Agent trace with the `Retrieve` tool call expanded
- [ ] Guardrail configuration page
- [ ] One blocked injection, one blocked denied topic
- [ ] CloudWatch alarms list and log groups list
- [ ] `evidence/` contains `state.json`, `discovery/`, `iam/`, `transcripts/baseline/`, `transcripts/hardened/`, `test_results_*.json`

**10.2** Dry run the teardown and read what it will delete:

```powershell
.\.venv\Scripts\python.exe submission\scripts\99_teardown.py --dry-run
```

**10.3** Tear it all down:

```powershell
.\.venv\Scripts\python.exe submission\scripts\99_teardown.py --yes
```

**10.4** Verify nothing is left billing:

```powershell
.\.venv\Scripts\python.exe submission\scripts\99_teardown.py --verify
```

It must print `account is clean`. Anything listed, delete in the console before
closing the lab.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `ExpiredToken` / `InvalidClientTokenId` | Cloud Lab session credentials rotated | Re-copy from the Cloud Resources tab, re-export the three env vars |
| `AccessDeniedException ... bedrock:ApplyGuardrail` | Guardrail attached without the IAM grant | `30_guardrail.py --attach` adds it; check with `--status` |
| `Model produced invalid sequence as part of ToolUse` | Unsupported model on tool calls | Switch the harness model to Claude Haiku 4.5, Sonnet 4.5/4.6, or Nova 2 Lite |
| Agent answers but never retrieves | Gateway tool not attached | Harness → Edit → Tools → Gateway |
| `10_discover.py` cannot find the KB | Managed KB not listing via the API | Re-run with `--kb-id <id>` from the console URL |
| Harness broken after IAM narrowing | Over-tightened policy | `20_harden_iam.py --restore` |
| Throttling during the test run | Concurrency limits | Re-run with `--delay 3` |
