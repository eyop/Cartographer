"""PDF generation — wire this up in week 7.

Plan: render ThreatProfile.summary as the executive summary page, then one
appendix page per source listing raw findings with attribution. Never let a
synthesized claim appear without a citation back to a RawFinding — that
distinction is what makes the report defensible to hand to a client."""

from ..models.entity import ThreatProfile


async def render_report_pdf(profile: ThreatProfile) -> bytes:
    raise NotImplementedError("Implement in week 7 using the pdf skill / reportlab / weasyprint")
