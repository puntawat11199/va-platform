"""
pdf_report.py - PDF scan report generator for the VA Platform.

Generates a professional PDF report from a completed scan including:
  - Cover page: target, scan ID, date, status, duration
  - Executive summary: finding counts by severity
  - Findings breakdown by scanner tool
  - Full findings table sorted critical-first
"""

from datetime import datetime, timezone
from fpdf import FPDF, XPos, YPos
from db.models import Scan, SeverityLevel, ScannerTool


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLOURS = {
    "header_bg":   (30,  30,  50),
    "header_text": (255, 255, 255),
    "section_bg":  (45,  45,  75),
    "section_text":(255, 255, 255),
    "row_alt":     (240, 240, 248),
    "row_norm":    (255, 255, 255),
    "border":      (200, 200, 210),
    "CRITICAL":    (180,  30,  30),
    "HIGH":        (220, 100,  20),
    "MEDIUM":      (200, 160,   0),
    "LOW":         ( 30, 100, 180),
    "INFO":        (120, 120, 130),
    "ZAP":         (100,  50, 160),
    "NUCLEI":      ( 20, 140, 140),
    "TESTSSL":     ( 30, 150,  60),
    "NMAP":        (200,  80,  20),
    "COMPLETED":   ( 30, 150,  60),
    "FAILED":      (180,  30,  30),
    "RUNNING":     ( 30, 100, 180),
    "PENDING":     (130, 130, 130),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class VAPlatformPDF(FPDF):
    def __init__(self, scan: Scan):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.scan = scan
        self.set_margins(12, 12, 12)
        self.set_auto_page_break(auto=True, margin=15)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_fill(self, key: str):
        r, g, b = COLOURS[key]
        self.set_fill_color(r, g, b)

    def _set_text(self, key: str):
        r, g, b = COLOURS[key]
        self.set_text_color(r, g, b)

    def _reset_text(self):
        self.set_text_color(30, 30, 30)

    def _section_header(self, title: str):
        self.ln(4)
        self._set_fill("section_bg")
        self._set_text("section_text")
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, f"  {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self._reset_text()
        self.ln(2)

    # ------------------------------------------------------------------
    # Header / Footer
    # ------------------------------------------------------------------

    def header(self):
        if self.page_no() == 1:
            return
        self._set_fill("header_bg")
        self.rect(0, 0, 297, 10, "F")
        self._set_text("header_text")
        self.set_font("Helvetica", "B", 8)
        self.set_xy(12, 2)
        self.cell(0, 6, "VA Automation Platform - Vulnerability Assessment Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self._reset_text()
        self.set_y(12)

    def footer(self):
        self.set_y(-10)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        self.cell(0, 6, f"Page {self.page_no()} - Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} - CONFIDENTIAL", align="C")
        self._reset_text()

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def cover_page(self):
        self.add_page()

        # Dark banner
        self._set_fill("header_bg")
        self.rect(0, 0, 297, 60, "F")

        self._set_text("header_text")
        self.set_font("Helvetica", "B", 22)
        self.set_xy(12, 14)
        self.cell(0, 12, "Vulnerability Assessment Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font("Helvetica", "", 11)
        self.set_x(12)
        self.cell(0, 7, "VA Automation Platform - Automated Security Scan Results", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self._reset_text()

        # Meta info box
        self.set_y(70)
        self._section_header("Scan Information")

        scan = self.scan
        status_str = scan.status.value if scan.status else "UNKNOWN"
        duration = ""
        if scan.started_at and scan.finished_at:
            secs = int((scan.finished_at - scan.started_at).total_seconds())
            duration = f"{secs // 60}m {secs % 60}s"

        rows = [
            ("Scan ID",       str(scan.id)),
            ("Target",        scan.target),
            ("Status",        status_str),
            ("Active Scan",   "Yes" if scan.active_scan else "No (passive only)"),
            ("Created",       scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "-"),
            ("Started",       scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "-"),
            ("Finished",      scan.finished_at.strftime("%Y-%m-%d %H:%M UTC") if scan.finished_at else "-"),
            ("Duration",      duration or "-"),
        ]

        self.set_font("Helvetica", "", 9)
        for label, value in rows:
            self.set_font("Helvetica", "B", 9)
            self.cell(45, 6, label, border="B")
            self.set_font("Helvetica", "", 9)
            self.cell(0, 6, value, border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def summary_page(self, vulns):
        self.add_page()
        self._section_header("Executive Summary")

        # Count by severity
        counts = {s: 0 for s in SEVERITY_ORDER}
        for v in vulns:
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            counts[sev] = counts.get(sev, 0) + 1

        total = sum(counts.values())

        # Summary stat boxes
        box_w = 50
        self.set_font("Helvetica", "B", 9)
        x_start = self.get_x()

        for sev in SEVERITY_ORDER:
            r, g, b = COLOURS[sev]
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255)
            self.cell(box_w, 12, f"{sev}  {counts[sev]}", align="C", fill=True, border=1)
        self.ln(12)
        self._reset_text()

        self.set_font("Helvetica", "", 9)
        self.ln(2)
        self.cell(0, 6, f"Total findings: {total}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Bar chart (text-based)
        self.ln(4)
        self._section_header("Severity Distribution")
        bar_max_w = 200
        self.set_font("Helvetica", "", 8)
        for sev in SEVERITY_ORDER:
            count = counts[sev]
            pct = (count / total * 100) if total else 0
            bar_w = int(bar_max_w * pct / 100) if total else 0
            r, g, b = COLOURS[sev]
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255) if bar_w > 20 else self._reset_text()
            self.set_font("Helvetica", "B", 8)
            self.cell(22, 5, sev, align="R")
            self.set_x(self.get_x() + 2)
            self.set_fill_color(r, g, b)
            if bar_w:
                self.cell(bar_w, 5, f" {count} ({pct:.1f}%)", fill=True)
            else:
                self._reset_text()
                self.cell(30, 5, f"{count} (0%)")
            self.ln(6)
        self._reset_text()

        # Breakdown by scanner
        self.ln(4)
        self._section_header("Findings by Scanner")
        tool_counts: dict[str, int] = {}
        for v in vulns:
            tool = v.tool.value if hasattr(v.tool, "value") else str(v.tool)
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        self.set_font("Helvetica", "B", 9)
        for tool, count in sorted(tool_counts.items()):
            r, g, b = COLOURS.get(tool, (80, 80, 80))
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255)
            self.cell(30, 6, tool, fill=True, align="C")
            self._reset_text()
            self.set_font("Helvetica", "", 9)
            self.cell(20, 6, str(count), border="B")
            self.set_font("Helvetica", "B", 9)
            self.ln(7)
        self._reset_text()

    # ------------------------------------------------------------------
    # Findings table
    # ------------------------------------------------------------------

    def findings_table(self, vulns):
        self.add_page()
        self._section_header(f"All Findings ({len(vulns)} total) - sorted Critical first")

        # Column widths (landscape A4 = 273mm usable)
        cols = [
            ("Severity",    22),
            ("Tool",        18),
            ("Title",       90),
            ("Target",      55),
            ("Parameter",   35),
            ("Evidence",    53),
        ]

        # Table header
        self.set_font("Helvetica", "B", 7)
        self._set_fill("header_bg")
        self._set_text("header_text")
        for label, w in cols:
            self.cell(w, 6, label, fill=True, border=1)
        self.ln()
        self._reset_text()

        # Sort: critical first
        sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: sev_rank.get(v.severity.value if hasattr(v.severity, "value") else str(v.severity), 99)
        )

        self.set_font("Helvetica", "", 6.5)
        for i, v in enumerate(sorted_vulns):
            sev   = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            tool  = v.tool.value if hasattr(v.tool, "value") else str(v.tool)
            title = (v.title or "")[:80]
            target = (v.target or "")[:45]
            param  = (v.parameter or "")[:28]
            evid   = (v.evidence or "")[:40]

            # Row background
            if i % 2 == 0:
                self.set_fill_color(*COLOURS["row_norm"])
            else:
                self.set_fill_color(*COLOURS["row_alt"])

            row_h = 5

            # Severity cell - coloured
            r, g, b = COLOURS.get(sev, (80, 80, 80))
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255)
            self.set_font("Helvetica", "B", 6.5)
            self.cell(cols[0][1], row_h, sev, fill=True, border=1)

            # Tool cell - coloured
            r, g, b = COLOURS.get(tool, (80, 80, 80))
            self.set_fill_color(r, g, b)
            self.cell(cols[1][1], row_h, tool, fill=True, border=1)

            # Rest of row
            self._reset_text()
            self.set_font("Helvetica", "", 6.5)
            if i % 2 == 0:
                self.set_fill_color(*COLOURS["row_norm"])
            else:
                self.set_fill_color(*COLOURS["row_alt"])

            self.cell(cols[2][1], row_h, title,  fill=True, border=1)
            self.cell(cols[3][1], row_h, target, fill=True, border=1)
            self.cell(cols[4][1], row_h, param,  fill=True, border=1)
            self.cell(cols[5][1], row_h, evid,   fill=True, border=1)
            self.ln()

        self._reset_text()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_scan_pdf(scan: Scan, vulns: list) -> bytes:
    """
    Generate a PDF report for the given scan and its findings.
    Returns the raw PDF bytes ready to stream as a response.
    """
    pdf = VAPlatformPDF(scan)
    pdf.cover_page()
    pdf.summary_page(vulns)
    pdf.findings_table(vulns)
    return bytes(pdf.output())
