"""
Board-ready posture PDF — the executive one-pager you hand to the board.

Turns the same posture timeline behind the dashboard chart into a printable, self-contained
report: the current risk score, the trend over the window, a risk-over-time line chart, the
current severity breakdown, and a plain-English note on how the score is computed (so it's
defensible in a compliance review). Generated server-side so it can also be emailed or attached
to scheduled reports later. Pure: `build_posture_pdf` takes a plain dict and returns PDF bytes,
so it's unit-testable without a backend.
"""

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing, Line, Polygon, PolyLine, String, Circle
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Project palette — severity hexes match the frontend (tailwind.config.ts) so the printed
# report reads the same as the dashboard the client already knows.
INK = colors.HexColor("#0d1117")
MUTED = colors.HexColor("#57606a")
HAIRLINE = colors.HexColor("#d0d7de")
ACCENT = colors.HexColor("#2f81f7")
GOOD = colors.HexColor("#1a7f37")  # risk falling = good
BAD = colors.HexColor("#cf222e")  # risk rising = bad

SEVERITY = [
    ("critical", "Critical", colors.HexColor("#ff4444")),
    ("high", "High", colors.HexColor("#ff8c00")),
    ("medium", "Medium", colors.HexColor("#d4a700")),
    ("low", "Low", colors.HexColor("#58a6ff")),
]


def _fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%b %d")
    except ValueError:
        return iso


def _risk_chart(timeline: list[dict], width: float, height: float) -> Drawing:
    """Vector line chart of risk_score over the window. Lower is better, so a falling line is
    the headline story. Hand-drawn (not a stock chart) to keep full control of the look."""
    d = Drawing(width, height)
    pad_l, pad_r, pad_t, pad_b = 28, 8, 12, 22
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    x0, y0 = pad_l, pad_b

    scores = [int(p.get("risk_score", 0) or 0) for p in timeline]
    y_max = max(scores + [1])
    # Round the axis ceiling up to something readable.
    y_top = max(5, ((y_max + 4) // 5) * 5)
    n = len(scores)

    def px(i: int) -> float:
        return x0 + (plot_w * (i / (n - 1)) if n > 1 else plot_w / 2)

    def py(v: float) -> float:
        return y0 + plot_h * (v / y_top)

    # Horizontal gridlines + y labels (0, mid, top).
    for frac in (0.0, 0.5, 1.0):
        gy = y0 + plot_h * frac
        d.add(Line(x0, gy, x0 + plot_w, gy, strokeColor=HAIRLINE, strokeWidth=0.5))
        d.add(String(x0 - 6, gy - 3, str(round(y_top * frac)),
                     fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="end"))

    pts = [(px(i), py(v)) for i, v in enumerate(scores)]

    if n == 1:
        # A single snapshot can't draw a trend — show the lone point.
        cx, cy = pts[0]
        d.add(Circle(cx, cy, 3, fillColor=ACCENT, strokeColor=ACCENT))
    else:
        # Filled area under the line for visual weight: bottom-left → line → bottom-right.
        area = [pts[0][0], y0] + [c for p in pts for c in p] + [pts[-1][0], y0]
        d.add(Polygon(points=area, fillColor=colors.HexColor("#ddeaff"), strokeColor=None))
        d.add(PolyLine(points=[c for p in pts for c in p], strokeColor=ACCENT, strokeWidth=2))
        # Emphasise the latest point.
        d.add(Circle(pts[-1][0], pts[-1][1], 3, fillColor=ACCENT, strokeColor=colors.white, strokeWidth=1))

    # X labels: first and last date (and middle if room).
    label_idx = {0, n - 1}
    if n >= 3:
        label_idx.add(n // 2)
    for i in sorted(label_idx):
        d.add(String(px(i), y0 - 12, _fmt_date(timeline[i].get("date", "")),
                     fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="middle"))

    # Axes.
    d.add(Line(x0, y0, x0 + plot_w, y0, strokeColor=HAIRLINE, strokeWidth=1))
    return d


def build_posture_pdf(report: dict) -> bytes:
    """Render the board report to PDF bytes.

    `report` shape:
      {org_name, days, timeline: [{date, risk_score, critical, high, ...}], current, trend_delta}
    `current` may be None (no history) — the report still renders with an empty state.
    """
    org_name = report.get("org_name") or "Your organization"
    days = int(report.get("days") or 90)
    timeline = report.get("timeline") or []
    current = report.get("current")
    delta = int(report.get("trend_delta") or 0)

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=18 * mm, bottomMargin=16 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
        title=f"Security Posture Report — {org_name}",
        author="Horus",
    )

    base = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=base["Title"], fontSize=20, textColor=INK,
                        spaceAfter=2, alignment=0)
    sub = ParagraphStyle("sub", parent=base["Normal"], fontSize=9, textColor=MUTED)
    section = ParagraphStyle("section", parent=base["Normal"], fontSize=8, textColor=MUTED,
                             spaceBefore=14, spaceAfter=6, leading=10,
                             fontName="Helvetica-Bold")
    body = ParagraphStyle("body", parent=base["Normal"], fontSize=9, textColor=INK, leading=13)
    foot = ParagraphStyle("foot", parent=base["Normal"], fontSize=7.5, textColor=MUTED, leading=11)

    generated = datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M UTC")
    story: list = []

    story.append(Paragraph("Security Posture Report", h1))
    story.append(Paragraph(
        f"{org_name} &nbsp;·&nbsp; last {days} days &nbsp;·&nbsp; generated {generated}", sub))
    story.append(Spacer(1, 10))

    # ── Headline: current risk score + trend ────────────────────────────────────
    if current:
        improving = delta < 0
        flat = delta == 0
        trend_color = MUTED if flat else (GOOD if improving else BAD)
        arrow = "→" if flat else ("▼" if improving else "▲")
        trend_word = "no change" if flat else (f"{arrow} {abs(delta)} lower" if improving
                                               else f"{arrow} {delta} higher")
        verdict = ("Risk is trending down over the window." if improving and not flat
                   else "Risk is flat over the window." if flat
                   else "Risk has risen over the window — see open findings below.")

        score_style = ParagraphStyle("score", parent=body, fontSize=40, leading=42,
                                     textColor=INK, fontName="Helvetica-Bold")
        trend_style = ParagraphStyle("trend", parent=body, fontSize=12, textColor=trend_color,
                                     fontName="Helvetica-Bold")
        head_tbl = Table(
            [[Paragraph(str(current.get("risk_score", 0)), score_style),
              Paragraph(f"{trend_word}<br/><font color='#57606a' size='8'>"
                        f"vs. {days} days ago · lower is better</font>", trend_style)]],
            colWidths=[45 * mm, None],
        )
        head_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(head_tbl)
        story.append(Paragraph(
            "<font size='8' color='#57606a'>RISK SCORE</font>", foot))
        story.append(Spacer(1, 4))
        story.append(Paragraph(verdict, body))

        # ── Chart ────────────────────────────────────────────────────────────────
        story.append(Paragraph("RISK OVER TIME", section))
        story.append(_risk_chart(timeline, width=170 * mm, height=55 * mm))

        # ── Current severity breakdown ─────────────────────────────────────────────
        story.append(Paragraph("CURRENT OPEN FINDINGS", section))
        head = ["", "Critical", "High", "Medium", "Low", "KEV active", "Total open"]
        vals = ["Count"] + [str(current.get(k, 0)) for k, _, _ in SEVERITY] + [
            str(current.get("kev_active", 0)), str(current.get("open_findings", 0))]
        sev_tbl = Table([head, vals], colWidths=[24 * mm] + [21.5 * mm] * 6)
        style = [
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
            ("FONT", (0, 1), (0, 1), "Helvetica-Bold", 9),
            ("FONT", (1, 1), (-1, 1), "Helvetica", 12),
            ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
            ("TEXTCOLOR", (-1, 1), (-1, 1), INK),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, HAIRLINE),
            ("LINEBELOW", (0, 1), (-1, 1), 0.5, HAIRLINE),
        ]
        # Colour each severity count cell.
        for i, (_, _, color) in enumerate(SEVERITY, start=1):
            style.append(("TEXTCOLOR", (i, 1), (i, 1), color))
        if current.get("kev_active", 0):
            style.append(("TEXTCOLOR", (5, 1), (5, 1), BAD))
            style.append(("FONT", (5, 1), (5, 1), "Helvetica-Bold", 12))
        sev_tbl.setStyle(TableStyle(style))
        story.append(sev_tbl)
    else:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "No posture history yet. A snapshot is captured after every scan and once a day; "
            "run a scan to start the timeline.", body))

    # ── Methodology (keeps the number defensible in a compliance review) ────────────
    story.append(Paragraph("HOW THE RISK SCORE IS COMPUTED", section))
    story.append(Paragraph(
        "The risk score is a deterministic, severity-weighted count of <b>open</b> findings — no "
        "AI, no black box. Each finding contributes by severity (Critical 10, High 5, Medium 2, "
        "Low 1, Info 0), and every finding under active exploitation (CISA Known Exploited "
        "Vulnerabilities) adds a further 10. Lower is better; 0 means no open risk. The same number "
        "is captured daily, so the trend reflects real remediation — closing findings lowers it, "
        "new or newly-exploited findings raise it.", body))

    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Confidential — prepared for the board of " + org_name +
        ". Generated by Horus continuous security monitoring.", foot))

    doc.build(story)
    return buf.getvalue()
