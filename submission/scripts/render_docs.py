"""Render the Markdown deliverables to PDF, and the two templates to .docx.

Pipeline: Markdown -> pandoc -> typst -> PDF. There is no LaTeX, no
wkhtmltopdf and no typst CLI on this machine; typst is used as a Python
package from a separate .venv-docs so the project venv's requirements stay
clean.

Page geometry goes in YAML front matter, injected here rather than stored in
the source files. Passing it as `--variable=margin:x=2cm,y=2cm` makes pandoc
emit `margin: (: ,)`, which is a typst syntax error -- the nested map form
below is the one that works.

The two supplied .docx templates are rendered with `--reference-doc` pointed at
the original, so the output inherits the template's styles rather than
pandoc's defaults.

Usage:
  python render_docs.py            # everything
  python render_docs.py --pdf      # PDFs only
  python render_docs.py --docx     # .docx only
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ns_common import REPO, SUBMISSION, log

DOCS = SUBMISSION / "docs"
OUT = SUBMISSION / "deliverables"
DOCS_VENV = REPO / ".venv-docs" / "Scripts" / "python.exe"

# Markdown deliverables -> PDF. Title is what appears on the cover line.
PDF_DOCS = [
    ("launch-readiness-report.md",
     "Launch-Readiness Security Report - Northstar Assist"),
    ("iam-hardening-summary.md",
     "IAM Hardening Summary - Northstar Assist"),
    ("safety-controls.md",
     "Safety and Response Controls - Northstar Assist"),
    ("monitoring-and-ir-playbook.md",
     "Monitoring Plan and Incident Response Playbook - Northstar Assist"),
    ("corpus-classification.md",
     "Knowledge Base Corpus Classification - Northstar Assist"),
    ("test-results-hardened.md",
     "Security Test Results (Hardened) - Northstar Assist"),
    ("test-results-baseline.md",
     "Security Test Results (Baseline) - Northstar Assist"),
]

# Markdown -> .docx, rendered against the supplied template for styling.
DOCX_DOCS = [
    ("ml-bom.md", REPO / "project" / "ML-BOM Template.docx",
     "ML-BOM - Northstar Assist.docx"),
    ("stride-ml-threat-model.md", REPO / "project" / "STRIDE-ML Template.docx",
     "STRIDE-ML Threat Model - Northstar Assist.docx"),
]

FRONT_MATTER = """---
title: "{title}"
author: "Tarie Nosworthy"
date: "18 September 2026"
papersize: us-letter
fontsize: 10pt
linestretch: 1.15
margin:
  x: 2cm
  y: 2cm
---

"""


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def render_pdf(name: str, title: str) -> bool:
    src = DOCS / name
    if not src.exists():
        log(f"{name}: not found, skipping", "warn")
        return False

    body = src.read_text(encoding="utf-8")
    # Strip a leading H1 -- the front-matter title already provides it, and
    # keeping both puts the same heading on the page twice.
    lines = body.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
        body = "\n".join(lines).lstrip("\n")

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        md = tmpdir / "doc.md"
        typ = tmpdir / "doc.typ"
        md.write_text(FRONT_MATTER.format(title=title) + body, encoding="utf-8")

        # No --number-sections: the documents carry their own section numbers,
        # and pandoc's would stack on top of them ("1.1 1. What was assessed").
        result = subprocess.run(
            ["pandoc", str(md), "--to=typst", "--standalone",
             "--toc", "--toc-depth=3", "-o", str(typ)],
            capture_output=True, text=True)
        if result.returncode != 0:
            log(f"{name}: pandoc failed - {result.stderr.strip()[:200]}", "err")
            return False

        pdf = OUT / (name.replace(".md", "") + ".pdf")
        # typst is a Python package here; there is no CLI binary on this box.
        code = (
            "import typst, sys\n"
            f"typst.compile(r'{typ}', output=r'{pdf}', root=r'{tmpdir}')\n"
        )
        result = subprocess.run([str(DOCS_VENV), "-c", code],
                                capture_output=True, text=True)
        if result.returncode != 0:
            log(f"{name}: typst failed - {result.stderr.strip()[:300]}", "err")
            return False

    size = pdf.stat().st_size // 1024
    log(f"{pdf.name} ({size} KB)", "ok")
    return True


def render_docx(name: str, reference: Path, out_name: str) -> bool:
    src = DOCS / name
    if not src.exists():
        log(f"{name}: not found, skipping", "warn")
        return False
    out = OUT / out_name
    cmd = ["pandoc", str(src), "-o", str(out), "--toc", "--toc-depth=3"]
    if reference.exists():
        cmd += [f"--reference-doc={reference}"]
    else:
        log(f"{reference.name} not found - using pandoc default styles", "warn")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log(f"{name}: pandoc failed - {result.stderr.strip()[:200]}", "err")
        return False
    log(f"{out.name} ({out.stat().st_size // 1024} KB)", "ok")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pdf", action="store_true")
    ap.add_argument("--docx", action="store_true")
    args = ap.parse_args()
    do_pdf = args.pdf or not args.docx
    do_docx = args.docx or not args.pdf

    if not have("pandoc"):
        log("pandoc not on PATH - cannot render", "err")
        return 1
    OUT.mkdir(parents=True, exist_ok=True)

    ok = fail = 0
    if do_docx:
        log("rendering .docx against the supplied templates", "step")
        for name, ref, out_name in DOCX_DOCS:
            if render_docx(name, ref, out_name):
                ok += 1
            else:
                fail += 1

    if do_pdf:
        if not DOCS_VENV.exists():
            log(f"{DOCS_VENV} missing - create it with:", "err")
            log("  py -3.11 -m venv .venv-docs", "err")
            log("  .\\.venv-docs\\Scripts\\python.exe -m pip install typst", "err")
            return 1
        log("rendering PDFs via pandoc -> typst", "step")
        for name, title in PDF_DOCS:
            if render_pdf(name, title):
                ok += 1
            else:
                fail += 1

    log(f"{ok} rendered, {fail} failed", "ok" if not fail else "warn")
    log(f"output -> {OUT.relative_to(REPO)}")
    return 0 if not fail else 2


if __name__ == "__main__":
    raise SystemExit(main())
