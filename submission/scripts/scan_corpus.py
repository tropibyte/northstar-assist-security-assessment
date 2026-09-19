"""Classify the Northstar knowledge base corpus before it is indexed.

Every document in northstar-knowledge-base/ is extracted to plain text and
scanned for (a) credential material, (b) direct-identifier PII, (c) internal
business identifiers, and (d) injection-shaped imperative text. The output is
the evidence base for the ML-BOM knowledge-source entry, the STRIDE-ML data
asset classification, the guardrail regex set, and the Task 7 elicitation
prompts -- so the controls are tuned to this corpus rather than to a guess.

Usage:  python scan_corpus.py [--json OUT.json] [--markdown OUT.md]
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "project" / "northstar-knowledge-base"

# --- detection rules -------------------------------------------------------
# Each rule: name, severity, compiled pattern. Severity drives classification.
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    # (a) credential material -- must never be retrievable by an assistant
    ("api_bearer_token", "CRITICAL", re.compile(r"\bns_(?:live|test)_[A-Za-z0-9]{6,}\b")),
    ("aws_access_key_id", "CRITICAL", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic_bearer", "CRITICAL", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}")),
    ("private_key_block", "CRITICAL", re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")),
    ("password_literal", "HIGH", re.compile(r"password[\"'\s:=]+(?!reset|policy|requirement)[^\s,<\"']{8,}", re.I)),

    # (b) direct-identifier PII
    ("internal_email", "HIGH", re.compile(r"\b[A-Za-z0-9._%+-]+@northstartech\.com\b")),
    ("external_email", "HIGH", re.compile(r"\b[A-Za-z0-9._%+-]+@(?!northstartech\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("us_phone", "MEDIUM", re.compile(r"\b(?:\+1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b")),
    ("ssn_like", "CRITICAL", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),

    # (c) internal business identifiers -- the join keys an attacker pivots on
    ("employee_id", "MEDIUM", re.compile(r"\bEMP\d{3}\b")),
    ("customer_id", "MEDIUM", re.compile(r"\bCUST\d{3}\b")),
    ("opportunity_id", "MEDIUM", re.compile(r"\bOPP-\d{4}-\d{3}\b")),
    ("ticket_id", "LOW", re.compile(r"\bTKT-\d{4}-\d{4}\b")),
    ("ec2_instance_id", "MEDIUM", re.compile(r"\bi-[0-9a-z]{8,17}\b")),
    ("aws_account_id", "HIGH", re.compile(r"\b\d{12}\b")),

    # (d) injection-shaped imperative text sitting inside retrievable content.
    # Retrieved chunks are NOT screened by the input guardrail, so imperative
    # second-person text in the corpus is the indirect-injection attack surface.
    ("imperative_instruction", "HIGH", re.compile(
        r"(?:ignore (?:all |any )?(?:previous|prior|above)|disregard (?:the |all )?(?:above|previous)"
        r"|you are now|new instructions?:|system prompt|reveal (?:your|the) (?:instructions|prompt))", re.I)),
]

# Financial / commercially sensitive column headers worth flagging in tabular data.
SENSITIVE_HEADERS = {
    "monthly_revenue", "deal_size", "salary", "compensation", "monthly_cost",
    "contract_value", "budget", "amount", "cost", "revenue", "probability",
}


# --- extraction ------------------------------------------------------------
def extract(path: Path) -> str:
    """Return plain text for any of the six corpus formats, or '' on failure."""
    suffix = path.suffix.lower()
    try:
        if suffix in {".txt", ".csv"}:
            return path.read_text(encoding="utf-8", errors="replace")
        if suffix == ".html":
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="replace"), "html.parser")
            return soup.get_text("\n")
        if suffix == ".docx":
            import docx
            d = docx.Document(str(path))
            parts = [p.text for p in d.paragraphs]
            for table in d.tables:
                for row in table.rows:
                    parts.append("\t".join(c.text for c in row.cells))
            return "\n".join(parts)
        if suffix == ".xlsx":
            import openpyxl
            wb = openpyxl.load_workbook(str(path), data_only=True, read_only=True)
            out = io.StringIO()
            for ws in wb.worksheets:
                out.write(f"# sheet: {ws.title}\n")
                for row in ws.iter_rows(values_only=True):
                    out.write("\t".join("" if c is None else str(c) for c in row) + "\n")
            wb.close()
            return out.getvalue()
        if suffix == ".pdf":
            from pypdf import PdfReader
            return "\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)
    except Exception as exc:  # a format we cannot read is itself worth reporting
        return f"<<EXTRACTION_FAILED: {exc}>>"
    return ""


def tabular_headers(path: Path, text: str) -> list[str]:
    """Header names for tabular formats, used to flag commercially sensitive columns."""
    if path.suffix.lower() == ".csv":
        first = text.splitlines()[0] if text.splitlines() else ""
        return [h.strip().lower() for h in next(csv.reader([first]), [])]
    if path.suffix.lower() == ".xlsx":
        heads: list[str] = []
        for line in text.splitlines():
            if line.startswith("# sheet:"):
                continue
            heads.extend(c.strip().lower() for c in line.split("\t") if c.strip())
            if heads:
                break
        return heads
    return []


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
# Classification follows the data-handling tiers used in the threat model.
TIER_BY_SEVERITY = {
    "CRITICAL": "RESTRICTED",
    "HIGH": "CONFIDENTIAL",
    "MEDIUM": "INTERNAL",
    "LOW": "INTERNAL",
    "NONE": "INTERNAL",
}


def scan() -> dict:
    if not CORPUS.is_dir():
        sys.exit(f"corpus not found: {CORPUS}")

    documents = []
    for path in sorted(CORPUS.rglob("*")):
        if not path.is_file():
            continue
        text = extract(path)
        findings: dict[str, dict] = {}
        for name, severity, pattern in RULES:
            matches = pattern.findall(text)
            if not matches:
                continue
            uniq = sorted({m if isinstance(m, str) else m[0] for m in matches})
            findings[name] = {
                "severity": severity,
                "count": len(matches),
                "distinct": len(uniq),
                # Samples are redacted for CRITICAL rules: the report is a
                # deliverable, and copying a secret into it just moves the leak.
                "samples": ["<redacted>"] * min(2, len(uniq)) if severity == "CRITICAL"
                           else uniq[:3],
            }

        headers = tabular_headers(path, text)
        sensitive_cols = sorted(set(headers) & SENSITIVE_HEADERS)
        worst = max((f["severity"] for f in findings.values()),
                    key=lambda s: SEVERITY_ORDER[s], default="NONE")
        if sensitive_cols and SEVERITY_ORDER[worst] < SEVERITY_ORDER["HIGH"]:
            worst = "HIGH"  # revenue/deal-size columns are confidential on their own

        documents.append({
            "path": str(path.relative_to(CORPUS)).replace("\\", "/"),
            "format": path.suffix.lower().lstrip("."),
            "bytes": path.stat().st_size,
            "chars": len(text),
            "classification": TIER_BY_SEVERITY[worst],
            "max_severity": worst,
            "sensitive_columns": sensitive_cols,
            "findings": findings,
        })

    totals = Counter()
    for doc in documents:
        totals[doc["classification"]] += 1
    rule_totals = Counter()
    for doc in documents:
        for name, f in doc["findings"].items():
            rule_totals[name] += f["count"]

    return {
        "corpus_root": str(CORPUS),
        "document_count": len(documents),
        "classification_totals": dict(totals),
        "rule_totals": dict(rule_totals.most_common()),
        "documents": documents,
    }


def to_markdown(report: dict) -> str:
    lines = [
        "# Northstar Assist - Knowledge Base Corpus Classification",
        "",
        f"Documents scanned: **{report['document_count']}**  ",
        "Scanner: `submission/scripts/scan_corpus.py` (deterministic regex rules, no model calls)",
        "",
        "Every document below is retrievable by the agent through the gateway's",
        "`Retrieve` tool. Retrieved chunks are placed directly into the model's",
        "context window **without passing through the input guardrail**, so the",
        "classification here defines the blast radius of a successful retrieval.",
        "",
        "## Classification summary",
        "",
        "| Tier | Documents |",
        "| --- | --- |",
    ]
    for tier in ("RESTRICTED", "CONFIDENTIAL", "INTERNAL"):
        lines.append(f"| {tier} | {report['classification_totals'].get(tier, 0)} |")
    lines += ["", "## Detections by rule", "", "| Rule | Occurrences |", "| --- | --- |"]
    for name, count in report["rule_totals"].items():
        lines.append(f"| `{name}` | {count} |")
    lines += ["", "## Per-document detail", "",
              "| Document | Format | Tier | Detections |", "| --- | --- | --- | --- |"]
    for doc in report["documents"]:
        det = ", ".join(f"{k} x{v['count']}" for k, v in doc["findings"].items()) or "-"
        if doc["sensitive_columns"]:
            det += f" - cols: {', '.join(doc['sensitive_columns'])}"
        lines.append(f"| `{doc['path']}` | {doc['format']} | {doc['classification']} | {det} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path, default=REPO / "submission/evidence/corpus_scan.json")
    ap.add_argument("--markdown", type=Path, default=REPO / "submission/docs/corpus-classification.md")
    args = ap.parse_args()

    report = scan()
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    args.markdown.write_text(to_markdown(report), encoding="utf-8")

    print(f"scanned {report['document_count']} documents")
    for tier, n in sorted(report["classification_totals"].items()):
        print(f"  {tier:<13} {n}")
    print(f"json     -> {args.json}")
    print(f"markdown -> {args.markdown}")


if __name__ == "__main__":
    main()
