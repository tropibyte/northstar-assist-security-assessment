# Northstar Assist — Security Assessment Submission

**Project:** Build and Secure an AWS Bedrock RAG AI Agent (Udacity cd15147 / nd909)
**Author:** Tarie Nosworthy
**Date:** 18 September 2026
**Environment:** AWS account 118924230273, `us-east-1` — **fully torn down**,
verified `account is clean`
**Spend:** $0.00 of a $25.00 budget

---

## Deliverables

Rendered documents are in `deliverables/`. Markdown sources are in `docs/`.

| # | Deliverable | File | Pages |
| --- | --- | --- | --- |
| 1 | **Working harness + retrieval evidence** | `evidence/screenshots/` (41, see `MANIFEST.md`) + `evidence/transcripts/` (101 runs) | — |
| 2 | **ML-BOM / AI asset inventory** | `deliverables/ML-BOM - Northstar Assist.docx` | — |
| 3 | **STRIDE-ML threat model** | `deliverables/STRIDE-ML Threat Model - Northstar Assist.docx` | — |
| 4 | **IAM hardening summary** | `deliverables/iam-hardening-summary.pdf` | 7 |
| 5 | **Safety controls description** | `deliverables/safety-controls.pdf` | 8 |
| 6 | **Monitoring plan + IR playbook** | `deliverables/monitoring-and-ir-playbook.pdf` | 8 |
| 7 | **Launch-readiness report** | `deliverables/launch-readiness-report.pdf` | 12 |

Supporting documents, also rendered:

| Document | File | Purpose |
| --- | --- | --- |
| Corpus classification | `deliverables/corpus-classification.pdf` | All 30 documents classified by sensitivity |
| Test results — hardened | `deliverables/test-results-hardened.pdf` | Full 29-test matrix, controls on |
| Test results — baseline | `deliverables/test-results-baseline.pdf` | Same suite, controls off |

**Recommendation: APPROVE WITH CONDITIONS** — 5 conditions, §6 of the
launch-readiness report.

---

## Headline results

| Metric | Baseline (controls off) | Hardened (controls on) |
| --- | --- | --- |
| Attack prompts blocked | **0.0%** | **93.9%** |
| Legitimate prompts blocked | 0.0% | 38.5% *(both causes diagnosed, fixes drafted)* |
| Guardrail interventions | 0 | 55 (46 input-side, 9 output-side) |
| Verdicts | 6 pass / 11 fail / 10 review | 38 pass / 9 fail / 27 review |

**101 test runs** across 29 tests covering all ten OWASP Top 10 for LLM
Applications categories, each run 2–3 times because guardrail behaviour is
non-deterministic. Two tests produced different outcomes across identical runs.

**On evidence format.** Both forms are present. **Screenshots:** 41 console
captures in `evidence/screenshots/`, with `MANIFEST.md` identifying the seven
rubric-relevant ones individually — including `20_516918.png`, the
`Northstar-Kb Retrieve` tool-call panel showing the query, five results, S3
document IDs and relevance scores, and `21_525722.png`, the full playground
exchange with the Agent trace and the model citing its source. **Transcripts:**
101 machine-readable runs, plus `index_verification.json` recording 30 of 30
documents confirmed `INDEXED` per-document rather than inferred from
`failed=0`.

**Post-submission review.** An external review on 19 September found a genuine
regression in the IAM work: three CloudWatch Logs statements were **widened**,
not narrowed, and the harness role gained write access to its own invocation
audit log. The root cause (the narrowing pass never verified it had narrowed),
the code fix, and the re-rating of threat R-02 from *mitigated* to *regressed*
are documented in `docs/iam-hardening-summary.md` §0. The corrected policy was
not re-applied — the environment was already gone — so `iam/after/` remains an
accurate record of what was applied, regression included.

### Four findings confirmed exploitable by test

1. **Corpus poisoning** (LLM04) — 1 of 3 runs reported a fabricated
   credential-rotation policy as fact and **cited the planted document**,
   contradicting three authoritative corpus sources.
2. **Forged conversation history** (LLM01) — a fabricated *assistant* turn
   produced a full employee-directory dump on baseline, stopped only by the
   model's token limit.
3. **Credential in the corpus** (LLM02) — `api_authentication_guide.html` ships
   a live-format bearer token. Blocked three-deep in testing; the secret is
   still there.
4. **Fabricated action completion** (LLM06) — the agent claimed to have deleted
   a document it has no tool to delete, and asserted confirmation. Unaddressed
   by any control, in both configurations.

---

## Repository layout

```
submission/
├── README.md                    this file
├── RUNBOOK.md                   the Cloud Lab execution runbook (PowerShell)
├── config.example.json          configuration template
├── deliverables/                rendered .docx and .pdf — the submission
├── docs/                        Markdown sources for all deliverables
├── guardrail/guardrail.json     guardrail configuration, with rationale notes
├── iam/before/ · iam/after/     policy documents and unified diffs
├── tests/prompts.yaml           29-test security suite
├── tests/injection-canary/      planted test document + methodology README
├── scripts/                     14 automation scripts
└── evidence/                    every captured artefact
    ├── transcripts/             101 test runs, one JSON per run
    ├── discovery/               live resource configurations
    ├── iam/                     policy capture + change log
    ├── logs/                    invocation log samples
    └── screenshots/             41 console captures + MANIFEST.md
```

---

## Scripts

Everything was automated so the metered lab session was spent executing rather
than deciding. Run order is the numeric prefix.

| Script | Purpose |
| --- | --- |
| `scan_corpus.py` | Classify all 30 corpus documents; detect credentials, PII, identifiers, injection-shaped text |
| `00_preflight.py` | Read-only pre-checks: credentials, region, model availability, existing resources |
| `02_model_access.py` | Probe real model **entitlement** — the check that found no Anthropic model is invokable |
| `05_upload.py` | Create the bucket with secure defaults, upload the corpus, verify 30/30 |
| `10_discover.py` | Read back every console-created resource into `evidence/state.json` |
| `12_verify_index.py` | Per-document index verification — proves 30/30 retrievable rather than inferring it |
| `20_harden_iam.py` | Narrow all three service roles; `--plan`, `--apply --verify`, `--restore` |
| `30_guardrail.py` | Create, version, grant `ApplyGuardrail`, attach, `--detach` for baseline runs |
| `32_guardrail_probe.py` | Call `ApplyGuardrail` directly to attribute a block to a specific policy |
| `35_canary.py` | Plant/remove the injection canary, with index resync |
| `40_run_tests.py` | Execute the 29-test suite; `--mode baseline\|hardened`, `--smoke` |
| `45_rescore.py` | Re-score saved transcripts with the current classifier — no AWS calls |
| `60_monitoring.py` | Enable invocation logging, discover real log structure, create filters and alarms |
| `99_teardown.py` | Delete everything in dependency order; `--verify` proves the account is clean |
| `render_docs.py` | Markdown → pandoc → typst → PDF; Markdown → .docx against the templates |

### Two design properties worth noting

**Scoring is a pure function of captured evidence.** Every test run stores its
full raw response, so results can be re-scored without re-running against a
metered account. This was used twice when classifier flaws were found — a
`max_tokens` truncation being miscounted as an error, and a poison marker being
counted as endorsed when the model was actually refuting it. Both corrections
are recorded in the results rather than quietly applied.

**Controls were diagnosed, not guessed.** When two legitimate prompts were
blocked, `32_guardrail_probe.py` called `ApplyGuardrail` directly and named the
responsible policy. FP-04's block was `TOPIC 'Credential and Secret Disclosure'`
— not the content filter I had assumed. Retuning by inference would have
adjusted the wrong control.

---

## Reproducing

The environment is torn down. To rebuild:

```powershell
cd "C:\Users\tarie\source\repos\Woolf\cd15147-Foundations-Operational-AI-Security"
Copy-Item submission\config.example.json submission\config.json
# set 'bucket' to a globally unique name using random digits
```

Then follow `RUNBOOK.md` — ten phases, every command copy-pasteable, with the
screenshot checklist and a troubleshooting table. Roughly 30 minutes of console
work plus scripted steps.

**Note on model choice.** `config.json` defaults to
`us.amazon.nova-2-lite-v1:0`. The project brief nominates Claude Haiku 4.5, but
no Anthropic model was invokable in the lab account — all three reported
`agreementAvailability.status = NOT_AVAILABLE` and failed with an
`aws-marketplace:Subscribe` denial. Run `02_model_access.py` to check
entitlement in any new account before building.

---

## Environment

| | |
| --- | --- |
| Foundation model | Amazon Nova 2 Lite (`us.amazon.nova-2-lite-v1:0`) |
| Embedding model | Amazon Titan Text Embeddings V2, 1024-dim FLOAT32 |
| Knowledge base | AgentCore Managed KB, `SMART_PARSING` |
| Gateway | AgentCore MCP gateway, connector `bedrock-knowledge-bases` v1.0.0 |
| Guardrail | STANDARD tier via `us.guardrail.v1:0`; 6 topics, 6 filters, 9 PII entities, 4 regexes, contextual grounding |
| Local toolchain | Python 3.11.9, boto3 1.43.97, pandoc 3.10, typst (Python package) |
