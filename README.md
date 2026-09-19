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
has no tool to perform. A post-submission review also found a regression in this
assessment's own IAM work — documented in
[`submission/docs/iam-hardening-summary.md`](submission/docs/iam-hardening-summary.md) §0
rather than quietly fixed.

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
