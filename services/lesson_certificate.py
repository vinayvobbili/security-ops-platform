"""Completion certificates for /lessons.

The certificate *facts* + verification code come from the model-agnostic
``quizforge.make_certificate``; this module is the application seam — it pulls the
analyst's best score and first-pass date from the training DB, and renders the
branded artifact (HTML context for the page, a reportlab PDF for download).

Brand anchors: blue #0046AD, green #00A651, gold for distinction.
"""

import io
import logging
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from quizforge import Certificate, make_certificate

from services import training_db

logger = logging.getLogger(__name__)

_ET = ZoneInfo("America/New_York")
# Optional house secret — when set, verification codes are unforgeable without it.
_SECRET = os.environ.get("CERT_VERIFY_SECRET", "")

BRAND_BLUE = "#0046AD"
BRAND_GREEN = "#00A651"
GOLD = "#D4A017"

ISSUER = "Cyber Security Detection & Response"


def _award_date(ts: str | None) -> str:
    """Format a stored UTC ISO timestamp as a US 'Month DD, YYYY' award date."""
    if not ts:
        return datetime.now(_ET).strftime("%B %-d, %Y")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(_ET).strftime("%B %-d, %Y")
    except (ValueError, TypeError):
        return datetime.now(_ET).strftime("%B %-d, %Y")


def build_certificate(email: str, name: str, topic_id: str, topic_title: str) -> Certificate | None:
    """Build the certificate for an analyst who has passed ``topic_id``.

    Returns ``None`` if they haven't passed it (no certificate to issue).
    """
    prog = training_db.get_user_progress(email).get(topic_id)
    if not prog or not prog.get("passed"):
        return None
    best_pct = round((prog.get("best_ratio") or 0.0) * 100)
    awarded_on = _award_date(training_db.get_first_pass_ts(email, topic_id))
    try:
        return make_certificate(
            learner_id=email, learner_name=name, topic_id=topic_id, topic_title=topic_title,
            score_pct=best_pct, awarded_on=awarded_on,
            pass_threshold=training_db.PASS_THRESHOLD,
            distinction_threshold=training_db.DISTINCTION_THRESHOLD,
            secret=_SECRET,
        )
    except ValueError:  # passed flag set but score below threshold — defensive
        return None


def _gradient_band(c, x, y, w, h, c0, c1, strips: int = 160) -> None:
    """Paint a left-to-right gradient rectangle as interpolated vertical strips.

    reportlab's axial-shading helper is finicky (floods the page), so we draw the
    band ourselves — robust across versions and keeps the rest of the page white.
    """
    sw = w / strips
    for i in range(strips):
        t = i / (strips - 1)
        c.setFillColorRGB(c0.red + (c1.red - c0.red) * t,
                          c0.green + (c1.green - c0.green) * t,
                          c0.blue + (c1.blue - c0.blue) * t)
        c.rect(x + i * sw, y, sw + 0.6, h, stroke=0, fill=1)


def render_pdf(cert: Certificate) -> bytes:
    """Render the certificate as a branded landscape PDF (reportlab).

    Base-14 Helvetica can't draw emoji, so the PDF is typographic — color, rules
    and a drawn seal carry the brand, not emoji glyphs (which would box-out).
    """
    from reportlab.lib.colors import HexColor, white
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.pdfgen import canvas

    width, height = landscape(letter)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(width, height))
    is_dist = cert.level == "distinction"
    blue = HexColor(BRAND_BLUE)
    green = HexColor(BRAND_GREEN)
    accent = HexColor(GOLD if is_dist else BRAND_GREEN)
    ink = HexColor("#444444")
    cx = width / 2

    # White page, then outer + inner decorative borders.
    c.setFillColor(white)
    c.rect(0, 0, width, height, stroke=0, fill=1)
    c.setStrokeColor(blue)
    c.setLineWidth(6)
    c.rect(28, 28, width - 56, height - 56)
    c.setStrokeColor(accent)
    c.setLineWidth(2)
    c.rect(40, 40, width - 80, height - 80)

    # Brand gradient header band (blue -> green), inside the borders.
    band_h = 96
    _gradient_band(c, 41, height - 40 - band_h, width - 82, band_h, blue, green)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(cx, height - 40 - band_h / 2 - 4, ISSUER.upper())
    c.setFont("Helvetica", 11)
    c.drawCentredString(cx, height - 40 - band_h / 2 - 26, "MYTHOS READINESS PROGRAM")

    # Title.
    c.setFillColor(blue)
    c.setFont("Helvetica-Bold", 40)
    c.drawCentredString(cx, height - 210, "Certificate of Completion")

    c.setFillColor(ink)
    c.setFont("Helvetica", 15)
    c.drawCentredString(cx, height - 244, "This certifies that")

    # Recipient + underline.
    c.setFillColor(HexColor("#0d2a52"))
    c.setFont("Helvetica-Bold", 34)
    c.drawCentredString(cx, height - 292, cert.learner_name)
    c.setStrokeColor(accent)
    c.setLineWidth(1.5)
    name_w = max(c.stringWidth(cert.learner_name, "Helvetica-Bold", 34), 220)
    c.line(cx - name_w / 2, height - 302, cx + name_w / 2, height - 302)

    # Body line + topic.
    level_txt = "completed with distinction" if is_dist else "successfully completed"
    c.setFillColor(ink)
    c.setFont("Helvetica", 15)
    c.drawCentredString(cx, height - 336, f"has {level_txt} the training lesson")
    c.setFillColor(blue)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(cx, height - 368, cert.topic_title)

    # Level + score line.
    chip = "DISTINCTION" if is_dist else "PASSED"
    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(cx, height - 402, f"{chip}     ·     SCORE {cert.score_pct}%")

    # Footer: date (left), seal (center), verification (right).
    fy = 86
    c.setFillColor(ink)
    c.setFont("Helvetica", 10)
    c.drawString(72, fy + 16, "AWARDED")
    c.setFillColor(blue)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(72, fy - 2, cert.awarded_on)

    c.setFillColor(ink)
    c.setFont("Helvetica", 10)
    c.drawRightString(width - 72, fy + 16, "VERIFICATION CODE")
    c.setFillColor(blue)
    c.setFont("Helvetica-Bold", 13)
    c.drawRightString(width - 72, fy - 2, cert.verification_code)

    c.setStrokeColor(accent)
    c.setLineWidth(3)
    c.circle(cx, fy + 8, 26, stroke=1, fill=0)
    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(cx, fy + 1, "★")

    c.showPage()
    c.save()
    return buf.getvalue()
