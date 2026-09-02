#!/usr/bin/env python3
"""Build the submission PDF with the unmodified USENIX 2027 style."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


PAPER_DIR = Path(__file__).resolve().parent
OFFICIAL_STYLE_SHA256 = (
    "2278c83173e084a00fcf76d3227acb971f5137ecea993a5b4e13a9b2bd67b45e"
)
PDF_SOURCE_DATE_EPOCH = 1788393600  # 2026-09-03T00:00:00Z, the result freeze.
CRITICAL_LOG_PATTERNS = (
    re.compile(r"LaTeX Warning: There were undefined references"),
    re.compile(r"LaTeX Warning: (?:Citation|Reference) .* undefined"),
    re.compile(r"Overfull \\[hv]box"),
    re.compile(r"Fatal error", re.IGNORECASE),
    re.compile(r"Emergency stop", re.IGNORECASE),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_official_style(path: Path) -> str:
    """Reject functional changes to the downloaded conference style.

    A single terminal newline is ignored because the upstream file has none.
    """

    payload = path.read_bytes()
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    digest = hashlib.sha256(payload).hexdigest()
    if digest != OFFICIAL_STYLE_SHA256:
        raise ValueError(
            "usenix.sty differs from the official USENIX Security 2027 file: "
            f"{digest} != {OFFICIAL_STYLE_SHA256}"
        )
    return digest


def _required_tool(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(
            f"{name} is required; install TeX Live or use the documented "
            "conference_paper/Dockerfile build"
        )
    return executable


def _run(args: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{detail}"
        )


def _capture(args: list[str]) -> str:
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{detail}"
        )
    return result.stdout


def validate_pdf_format(path: Path) -> dict[str, object]:
    """Check the desk-rejection-sensitive PDF properties available locally."""

    pdfinfo = _required_tool("pdfinfo")
    pdffonts = _required_tool("pdffonts")
    metadata: dict[str, str] = {}
    for line in _capture([pdfinfo, str(path)]).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip()
    if metadata.get("Page size") != "612 x 792 pts (letter)":
        raise RuntimeError("submission PDF is not U.S. Letter size")
    if metadata.get("Title") or metadata.get("Author"):
        raise RuntimeError("submission PDF metadata is not anonymous")
    try:
        pages = int(metadata["Pages"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("submission PDF has no valid page count") from exc
    if pages > 20:
        raise RuntimeError("submission PDF exceeds the 20-page total limit")

    font_lines = _capture([pdffonts, str(path)]).splitlines()[2:]
    if not font_lines:
        raise RuntimeError("submission PDF contains no detectable fonts")
    unembedded = []
    for line in font_lines:
        fields = line.split()
        if len(fields) < 8 or fields[-5] != "yes":
            unembedded.append(line)
    if unembedded:
        raise RuntimeError("submission PDF contains unembedded fonts")
    return {
        "pages": pages,
        "page_size": metadata["Page size"],
        "embedded_fonts": len(font_lines),
        "anonymous_metadata": True,
    }


def _copy_inputs(work: Path) -> None:
    required = (
        PAPER_DIR / "paper.tex",
        PAPER_DIR / "references.bib",
        PAPER_DIR / "usenix.sty",
    )
    generated = tuple(sorted(PAPER_DIR.glob("generated_*.tex")))
    figures = tuple(sorted((PAPER_DIR / "figures").glob("*.pdf")))
    if not generated or not figures:
        raise FileNotFoundError("generated LaTeX inputs or PDF figures are missing")
    for source in required + generated + figures:
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = work / source.relative_to(PAPER_DIR)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def build_pdf(output_dir: Path) -> dict[str, object]:
    """Compile in a clean directory and promote only verified build outputs."""

    style_digest = validate_official_style(PAPER_DIR / "usenix.sty")
    pdflatex = _required_tool("pdflatex")
    bibtex = _required_tool("bibtex")
    environment = os.environ.copy()
    environment.update(
        {
            "FORCE_SOURCE_DATE": "1",
            "SOURCE_DATE_EPOCH": str(PDF_SOURCE_DATE_EPOCH),
            "TZ": "UTC",
        }
    )
    latex_args = [
        pdflatex,
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-file-line-error",
        "paper.tex",
    ]

    with tempfile.TemporaryDirectory(prefix="warrantlab-paper-") as temporary:
        work = Path(temporary)
        _copy_inputs(work)
        _run(latex_args, cwd=work, env=environment)
        _run([bibtex, "paper"], cwd=work, env=environment)
        _run(latex_args, cwd=work, env=environment)
        _run(latex_args, cwd=work, env=environment)

        log_path = work / "paper.log"
        pdf_path = work / "paper.pdf"
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        violations = [
            pattern.pattern
            for pattern in CRITICAL_LOG_PATTERNS
            if pattern.search(log_text)
        ]
        if violations:
            raise RuntimeError(
                "submission PDF has critical LaTeX diagnostics: "
                + ", ".join(violations)
            )
        page_match = re.search(
            r"Output written on paper\.pdf \((\d+) pages?, (\d+) bytes\)",
            log_text,
        )
        if page_match is None:
            raise RuntimeError("final LaTeX log lacks the PDF page/size summary")

        format_summary = validate_pdf_format(pdf_path)
        if format_summary["pages"] != int(page_match.group(1)):
            raise RuntimeError("PDF metadata and LaTeX log page counts disagree")

        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        for name in ("paper.pdf", "paper.log", "paper.bbl", "paper.blg"):
            shutil.copyfile(work / name, output_dir / name)

    output_pdf = output_dir / "paper.pdf"
    return {
        "status": "passed",
        "compiler": "pdfLaTeX",
        "source_date_epoch": PDF_SOURCE_DATE_EPOCH,
        "official_style_sha256": style_digest,
        **format_summary,
        "bytes": output_pdf.stat().st_size,
        "pdf_sha256": _sha256(output_pdf),
        "output": str(output_pdf),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PAPER_DIR / "build",
        help="verified build directory (default: conference_paper/build)",
    )
    args = parser.parse_args()
    print(json.dumps(build_pdf(args.output_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
