# Northstar Assist — AI Security Assessment

Security assessment of a retrieval-augmented AI agent built on Amazon Bedrock
AgentCore: deployed, hardened, tested across all ten OWASP Top 10 for LLM
Applications categories, and decommissioned.

**➜ Start here: [`submission/README.md`](submission/README.md)**

Rendered deliverables are in [`submission/deliverables/`](submission/deliverables).
Console evidence is in
[`submission/evidence/screenshots/`](submission/evidence/screenshots) — 41
captures with a manifest identifying the rubric-relevant ones.

| | |
| --- | --- |
| Recommendation | **APPROVE WITH CONDITIONS** (5 conditions) |
| Attack prompts blocked | 0.0% baseline → **93.9%** hardened |
| Test runs | 101 across 29 tests, each run 2–3 times |
| Findings confirmed exploitable | 4, with verbatim agent output |
| AWS spend | $0.00 of a $25.00 budget; account verified torn down |

Four findings were confirmed by test: corpus poisoning succeeded in 1 of 3 runs
*and cited the planted document*; a forged assistant turn produced a full
employee-directory dump on the unguarded baseline; the supplied corpus ships a
live-format API bearer token; and the agent fabricated a document deletion it
has no tool to perform.

A post-submission review found a regression in this assessment's **own** IAM
work: the hardening pass had widened three CloudWatch Logs statements rather
than narrowing them, handing the agent's role write access to the log group
recording its own behaviour, while the write-up claimed the opposite. The
environment was rebuilt on 19 September and the corrected hardening applied and
verified against live IAM — **0 statements widened, 14 removed, 17 surviving
wildcards all individually justified, audit PASS**. Five statements the first
submission called "loose" were removed outright after testing showed nothing
called them.

The defect is documented in full in
[`submission/docs/iam-hardening-summary.md`](submission/docs/iam-hardening-summary.md) §0
rather than quietly fixed, and the first submission's evidence is preserved
unedited in `submission/iam/session1-2026-09-18/`.

Two checks make that reproducible from this repository with **no AWS
credentials**:

```bash
python submission/scripts/22_iam_audit.py      # re-derives the PASS from committed evidence
python submission/tests/test_no_widening.py    # 16 policies, 74 statements, 0 widened
```

And because a detector that has never caught anything is only a claim, pointing
the auditor at the preserved first-submission evidence makes it fail on demand:

```bash
python submission/scripts/22_iam_audit.py     --before submission/iam/session1-2026-09-18/before     --after  submission/iam/session1-2026-09-18/after --expect-fail
```

---

## Upstream

This repository began as a clone of Udacity's course starter,
[`udacity/cd15147-Foundations-Operational-AI-Security`](https://github.com/udacity/cd15147-Foundations-Operational-AI-Security),
which remains configured as the `upstream` remote. The original starter content
is unmodified:

- `project/` — the 30-document sample knowledge base, the two document
  templates, and the reference Streamlit app
- `module-*-name/` — the course's exercise placeholders, left as upstream
  provides them

All assessment work is confined to `submission/`.
