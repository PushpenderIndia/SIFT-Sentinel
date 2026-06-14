"""sift-sentinel-report — render a DFIR findings PDF from the audit trail.

This is deliberately **not** an MCP tool. The MCP server's guarantee is that the
agent's entire action space is read-only forensic functions — there is no tool
that writes to disk. Report generation is therefore a separate, offline step run
*after* the investigation, over data that already exists:

  * the findings narrative (markdown the analyst/agent produced), and
  * ``audit/execution-log.jsonl`` (the append-only record of every tool call).

Keeping it out of band preserves the read-only trust boundary while still
producing a court-friendly deliverable in which every claim can be traced to a
``call_id`` in the audit log.

The PDF is written by a tiny self-contained writer (no third-party dependency),
so it runs on an air-gapped SIFT Workstation with nothing but the stdlib.

Usage::

    sift-sentinel-report --audit audit/execution-log.jsonl \
        --findings report.md --case "BASE-DC intrusion" -o report.pdf
"""
from __future__ import annotations

import argparse
import re
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional

from .audit import AuditLog, AuditRecord

# US Letter, 0.75" margins, in PDF points (72 per inch).
PAGE_W, PAGE_H = 612.0, 792.0
MARGIN = 54.0
CONTENT_W = PAGE_W - 2 * MARGIN

# Logical font names mapped to the three base-14 fonts we embed by reference.
HELV, HELV_BOLD, COURIER = "F1", "F2", "F3"
_AVG_CHAR_W = {HELV: 0.50, HELV_BOLD: 0.53, COURIER: 0.60}  # fraction of font size

_CALL_ID_RE = re.compile(r"call-\d{6}")


# --------------------------------------------------------------------------- #
# Minimal PDF writer
# --------------------------------------------------------------------------- #
def _pdf_escape(text: str) -> bytes:
    """Escape a string for a PDF literal and encode it as WinAnsi (latin-1)."""
    out = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return out.encode("latin-1", "replace")


class _Pdf:
    """Accumulates absolutely-positioned text ops and serialises a valid PDF.

    Each op is ``(x, y, font, size, text)`` with the PDF origin at the bottom-left
    of the page. Layout (wrapping, pagination) is the caller's job; this class only
    knows how to emit bytes.
    """

    def __init__(self) -> None:
        self.pages: list[list[tuple[float, float, str, float, str]]] = []

    def new_page(self) -> list[tuple[float, float, str, float, str]]:
        page: list[tuple[float, float, str, float, str]] = []
        self.pages.append(page)
        return page

    def _content_stream(self, ops: list[tuple[float, float, str, float, str]]) -> bytes:
        chunks: list[bytes] = []
        for x, y, font, size, text in ops:
            chunks.append(
                b"BT /%s %s Tf 1 0 0 1 %s %s Tm (%s) Tj ET\n"
                % (
                    font.encode("ascii"),
                    b"%.2f" % size,
                    b"%.2f" % x,
                    b"%.2f" % y,
                    _pdf_escape(text),
                )
            )
        return b"".join(chunks)

    def to_bytes(self) -> bytes:
        if not self.pages:
            self.new_page()

        objects: list[bytes] = []  # body of each object, 1-indexed conceptually

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)  # object number

        catalog_num = add(b"")  # 1 — placeholder, filled after pages known
        pages_num = add(b"")    # 2 — placeholder
        f_helv = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        f_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        f_cour = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        font_res = (
            b"/Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >>"
            % (f_helv, f_bold, f_cour)
        )

        page_nums: list[int] = []
        for ops in self.pages:
            stream = self._content_stream(ops)
            content_num = add(
                b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
            )
            page_num = add(
                b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.0f %.0f] "
                b"/Resources << %s >> /Contents %d 0 R >>"
                % (pages_num, PAGE_W, PAGE_H, font_res, content_num)
            )
            page_nums.append(page_num)

        kids = b" ".join(b"%d 0 R" % n for n in page_nums)
        objects[pages_num - 1] = (
            b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_nums))
        )
        objects[catalog_num - 1] = (
            b"<< /Type /Catalog /Pages %d 0 R >>" % pages_num
        )

        # Serialise with an xref table.
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = []
        for i, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n%s\nendobj\n" % (i, body)

        xref_pos = len(out)
        n = len(objects) + 1
        out += b"xref\n0 %d\n" % n
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += (
            b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (n, catalog_num, xref_pos)
        )
        return bytes(out)


# --------------------------------------------------------------------------- #
# Layout: turn styled blocks into positioned text ops with wrapping + paging
# --------------------------------------------------------------------------- #
class _Layout:
    def __init__(self) -> None:
        self.pdf = _Pdf()
        self.page = self.pdf.new_page()
        self.y = PAGE_H - MARGIN

    def _newpage(self) -> None:
        self.page = self.pdf.new_page()
        self.y = PAGE_H - MARGIN

    def _wrap(self, text: str, font: str, size: float, indent: float) -> list[str]:
        avail = CONTENT_W - indent
        max_chars = max(8, int(avail / (size * _AVG_CHAR_W[font])))
        lines: list[str] = []
        for para in text.split("\n"):
            wrapped = textwrap.wrap(
                para, width=max_chars, break_long_words=True, break_on_hyphens=False
            )
            lines.extend(wrapped or [""])
        return lines

    def emit(
        self,
        text: str,
        *,
        font: str = HELV,
        size: float = 10.5,
        indent: float = 0.0,
        leading: Optional[float] = None,
        space_before: float = 0.0,
    ) -> None:
        leading = leading if leading is not None else size * 1.35
        if space_before:
            self.y -= space_before
        for line in self._wrap(text, font, size, indent):
            if self.y - leading < MARGIN:
                self._newpage()
            self.y -= leading
            self.page.append((MARGIN + indent, self.y, font, size, line))

    def spacer(self, h: float = 6.0) -> None:
        self.y -= h

    def bytes(self) -> bytes:
        return self.pdf.to_bytes()


# --------------------------------------------------------------------------- #
# Markdown -> blocks (pragmatic subset: headings, bullets, code, paragraphs)
# --------------------------------------------------------------------------- #
def _strip_inline(text: str) -> str:
    """Flatten inline markdown to plain text (bold, code, links)."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # [label](url) -> label
    text = text.replace("**", "").replace("`", "")
    return text


def _render_markdown(lay: _Layout, md: str) -> None:
    in_code = False
    para: list[str] = []

    def flush_para() -> None:
        if para:
            lay.emit(" ".join(para), space_before=3.0)
            para.clear()

    for raw in md.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            flush_para()
            in_code = not in_code
            continue
        if in_code:
            lay.emit(line or " ", font=COURIER, size=8.5, indent=10, leading=11)
            continue
        if not line.strip():
            flush_para()
            lay.spacer(4)
            continue
        if line.startswith("### "):
            flush_para()
            lay.emit(_strip_inline(line[4:]), font=HELV_BOLD, size=11.5, space_before=8)
        elif line.startswith("## "):
            flush_para()
            lay.emit(_strip_inline(line[3:]), font=HELV_BOLD, size=13.5, space_before=10)
        elif line.startswith("# "):
            flush_para()
            lay.emit(_strip_inline(line[2:]), font=HELV_BOLD, size=16, space_before=10)
        elif re.match(r"^\s*[-*]\s+", line):
            flush_para()
            body = _strip_inline(re.sub(r"^\s*[-*]\s+", "", line))
            lay.emit("• " + body, indent=12)
        elif re.match(r"^\s*\d+\.\s+", line):
            flush_para()
            lay.emit(_strip_inline(line.strip()), indent=12)
        else:
            para.append(_strip_inline(line.strip()))
    flush_para()


# --------------------------------------------------------------------------- #
# Audit appendix + chain-of-custody integrity check
# --------------------------------------------------------------------------- #
def _render_audit_appendix(lay: _Layout, records: list[AuditRecord]) -> None:
    lay.emit("Audit Trail", font=HELV_BOLD, size=13.5, space_before=12)
    lay.emit(
        f"{len(records)} tool invocation(s), append-only. Every finding above "
        "cites a call_id resolved here.",
        size=9.5,
    )
    lay.spacer(2)
    for r in records:
        status = "ERROR" if r.error else f"exit={r.exit_code}"
        head = (
            f"{r.call_id}  {r.tool}  [{status}]  {r.duration_ms or 0} ms  {r.ts}"
        )
        lay.emit(head, font=COURIER, size=8.5, leading=11, space_before=3)
        if r.binary:
            lay.emit(f"    binary: {r.binary}", font=COURIER, size=8, leading=10)
        if r.input_hash:
            lay.emit(f"    sha256: {r.input_hash}", font=COURIER, size=8, leading=10)
        if r.args:
            arg_str = ", ".join(f"{k}={v}" for k, v in r.args.items())
            lay.emit(f"    args: {arg_str}", font=COURIER, size=8, leading=10)
        if r.error:
            lay.emit(f"    error: {r.error}", font=COURIER, size=8, leading=10)


def _render_integrity(
    lay: _Layout, cited: set[str], known: set[str]
) -> None:
    lay.emit("Chain-of-Custody Integrity Check", font=HELV_BOLD, size=13.5, space_before=12)
    missing = sorted(cited - known)
    uncited = sorted(known - cited)
    if not cited:
        lay.emit(
            "No call_id citations were found in the findings narrative. Each claim "
            "should cite the call_id that produced it.",
            size=9.5,
        )
    elif missing:
        lay.emit(
            f"WARNING: {len(missing)} cited call_id(s) have no matching audit "
            "record — these claims are NOT traceable to a logged tool call:",
            font=HELV_BOLD,
            size=10,
        )
        for cid in missing:
            lay.emit(f"• {cid}", font=COURIER, size=9, indent=12)
    else:
        lay.emit(
            f"PASS: all {len(cited)} cited call_id(s) resolve to a logged tool "
            "invocation in the audit trail.",
            size=10,
        )
    if uncited:
        lay.emit(
            f"Note: {len(uncited)} logged call(s) are not cited in the findings "
            "(informational, not an error).",
            size=9,
            space_before=3,
        )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def build_report(
    *,
    audit_path: str,
    findings_md: Optional[str],
    case: Optional[str],
    evidence_root: Optional[str],
) -> bytes:
    """Assemble the full report PDF and return its bytes."""
    records = AuditLog(audit_path).records()
    lay = _Layout()

    # Header / cover block.
    lay.emit("SIFT-Sentinel Findings Report", font=HELV_BOLD, size=18, space_before=6)
    if case:
        lay.emit(f"Case: {case}", font=HELV_BOLD, size=11, space_before=4)
    generated = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
    lay.emit(f"Generated: {generated}", size=9.5)
    if evidence_root:
        lay.emit(f"Evidence root: {evidence_root}", size=9.5)
    lay.emit(f"Audit log: {audit_path}", size=9.5)
    lay.spacer(6)

    cited: set[str] = set()
    if findings_md:
        cited = set(_CALL_ID_RE.findall(findings_md))
        _render_markdown(lay, findings_md)
    else:
        lay.emit(
            "No findings narrative supplied; this report contains the audit trail "
            "only.",
            size=10,
            space_before=4,
        )

    known = {r.call_id for r in records}
    _render_integrity(lay, cited, known)
    _render_audit_appendix(lay, records)
    return lay.bytes()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sift-sentinel-report",
        description="Render a DFIR findings PDF from a findings narrative + the "
        "audit log. Read-only: never touches evidence.",
    )
    parser.add_argument(
        "--audit",
        default="audit/execution-log.jsonl",
        help="Path to the append-only audit log (JSONL).",
    )
    parser.add_argument(
        "-f", "--findings",
        help="Markdown file with the findings narrative. If omitted, the report "
        "contains the audit trail only.",
    )
    parser.add_argument(
        "-o", "--output", default="sift-sentinel-report.pdf",
        help="Output PDF path.",
    )
    parser.add_argument("--case", help="Case name/identifier for the header.")
    parser.add_argument(
        "--evidence-root", help="Evidence root, recorded in the header for context."
    )
    args = parser.parse_args(argv)

    findings_md: Optional[str] = None
    if args.findings:
        fp = Path(args.findings)
        if not fp.exists():
            print(f"findings file not found: {fp}", file=sys.stderr)
            return 2
        findings_md = fp.read_text(encoding="utf-8", errors="replace")

    pdf = build_report(
        audit_path=args.audit,
        findings_md=findings_md,
        case=args.case,
        evidence_root=args.evidence_root,
    )
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pdf)
    print(f"wrote {out} ({len(pdf)} bytes, {out.stat().st_size} on disk)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
