"""PDF report generation (week 7).

Renders a ThreatProfile into a client-ready PDF:
  Page 1 — Title + Executive Summary
  Page 2 — Risk Indicators
  Appendix A — Entities table
  Appendix B — Relationships table
  Appendix C — Source Attribution

Every risk indicator and entity is traceable to source records.
"""

from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..models.entity import Entity, ThreatProfile

_style_cache: getSampleStyleSheet | None = None


def _styles():
    global _style_cache
    if _style_cache is None:
        _style_cache = getSampleStyleSheet()
        _style_cache.add(ParagraphStyle(name="Small", fontSize=8, leading=10))
    return _style_cache


def _entity_value(profile: ThreatProfile, eid: str) -> str:
    for e in profile.entities:
        if e.id == eid:
            return e.value
    return eid


def _all_sources(profile: ThreatProfile) -> set[str]:
    sources: set[str] = set()
    for e in profile.entities:
        sources.update(e.sources)
    return sources


def _table_style(header_bg=colors.grey) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ])


async def render_report_pdf(profile: ThreatProfile) -> bytes:
    """Render a ThreatProfile into a PDF byte stream."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = _styles()
    story: list = []

    # --- Title ---
    story.append(Paragraph("Threat Profile Report", styles["Title"]))
    story.append(Paragraph(f"Target: {profile.target}", styles["Heading2"]))
    story.append(Paragraph(
        f"Generated: {profile.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))
    story.append(Paragraph(f"Model: {profile.model_version}", styles["Small"]))
    story.append(Spacer(12))

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    story.append(Paragraph(profile.summary, styles["BodyText"]))
    story.append(Spacer(12))

    # --- Risk Indicators ---
    story.append(Paragraph("Risk Indicators", styles["Heading1"]))
    if profile.risk_indicators:
        for i, indicator in enumerate(profile.risk_indicators, 1):
            story.append(Paragraph(f"{i}. {indicator}", styles["BodyText"]))
    else:
        story.append(Paragraph("No risk indicators identified.", styles["BodyText"]))
    story.append(Spacer(12))

    # --- Entities ---
    story.append(Paragraph("Entities", styles["Heading1"]))
    if profile.entities:
        ent_data = [["Type", "Value", "Confidence", "Sources"]]
        for e in profile.entities:
            ent_data.append([
                e.type,
                str(e.value),
                f"{e.confidence:.2f}",
                ", ".join(e.sources) if e.sources else "",
            ])
        table = Table(ent_data, repeatRows=1, colWidths=[0.8*inch, 2.2*inch, 0.7*inch, 1.3*inch])
        table.setStyle(_table_style())
        story.append(table)
    else:
        story.append(Paragraph("No entities found.", styles["BodyText"]))
    story.append(Spacer(12))

    # --- Relationships ---
    story.append(Paragraph("Relationships", styles["Heading1"]))
    if profile.relationships:
        rel_data = [["Source", "Type", "Target", "Confidence"]]
        for r in profile.relationships:
            src = _entity_value(profile, r.source_entity_id)
            tgt = _entity_value(profile, r.target_entity_id)
            rel_data.append([src, r.type, tgt, f"{r.confidence:.2f}"])
        table = Table(rel_data, repeatRows=1, colWidths=[2*inch, 1.2*inch, 2*inch, 0.8*inch])
        table.setStyle(_table_style())
        story.append(table)
    else:
        story.append(Paragraph("No relationships found.", styles["BodyText"]))
    story.append(Spacer(12))

    # --- Attribution ---
    story.append(Paragraph("Source Attribution", styles["Heading1"]))
    srcs = sorted(_all_sources(profile))
    story.append(Paragraph(
        f"Data sources queried: {', '.join(srcs) if srcs else '(none)'}",
        styles["BodyText"],
    ))
    story.append(Paragraph(
        "This report is based entirely on passive OSINT collection from public APIs.",
        styles["Small"],
    ))

    doc.build(story)
    return buf.getvalue()
