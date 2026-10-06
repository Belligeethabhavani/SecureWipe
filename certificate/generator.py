
import os
import uuid
import hashlib
import io
from datetime import datetime

import qrcode
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image as RLImage
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

from core.keystore import get_or_create_device_key
from certificate.signer import build_record, sign_record, _canonical_bytes


SIG_BEGIN = b"%%SECUREWIPE_V1_SIG_BEGIN%%\n"
SIG_END   = b"\n%%SECUREWIPE_V1_SIG_END%%\n"


def generate_certificate(wiped_files: dict, algorithm: str, passes: int,
                         output_path: str = None,
                         storage_devices: list = None) -> tuple:
    
    timestamp  = datetime.now()
    cert_id    = str(uuid.uuid4()).upper()

    if not output_path:
        safe_ts     = timestamp.strftime("%Y%m%d_%H%M%S")
        output_path = f"SecureWipe_Certificate_{safe_ts}.pdf"
    
    pdf_path = output_path

    # Get device key + fingerprint 
    private_key, pub_bytes, device_fp = get_or_create_device_key()
    pub_hex = pub_bytes.hex()

    # Build the PDF 
    _build_pdf(pdf_path, cert_id, timestamp, algorithm, passes,
               wiped_files, pub_hex, device_fp, storage_devices)

    # Hash the entire PDF 
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    pdf_hash = hashlib.sha256(pdf_bytes).digest()

    # Sign the hash 
    signature_hex = private_key.sign(pdf_hash).hex()

    # Append signature block after 
    with open(pdf_path, "ab") as f:
        f.write(SIG_BEGIN)
        f.write(signature_hex.encode("ascii"))
        f.write(SIG_END)

    return (pdf_path,)



def _build_pdf(path, cert_id, timestamp, algorithm, passes,
               wiped_files, pub_hex, device_fp, storage_devices):
    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm, bottomMargin=18*mm,
    )

    S = getSampleStyleSheet()
    def sty(name, **kw):
        return ParagraphStyle(name, parent=S["Normal"], **kw)

    title_s = sty("Ti", fontSize=22, fontName="Helvetica-Bold",
                  textColor=colors.HexColor("#0d1117"),
                  spaceBefore=4, spaceAfter=6)
    sub_s   = sty("Su", fontSize=9.5, textColor=colors.HexColor("#57606a"),
                  spaceAfter=3, leading=14)
    sec_s   = sty("Se", fontSize=11, fontName="Helvetica-Bold",
                  textColor=colors.HexColor("#0550ae"), spaceBefore=10, spaceAfter=5)
    mono_s  = sty("Mo", fontSize=6.5, fontName="Courier",
                  textColor=colors.HexColor("#0550ae"), leading=9, wordWrap='LTR')
    cell_s  = sty("Ce", fontSize=7.5, textColor=colors.HexColor("#24292f"),
                  leading=10, wordWrap='LTR')
    body_s  = sty("Bo", fontSize=8.5, textColor=colors.HexColor("#24292f"), leading=12)
    foot_s  = sty("Fo", fontSize=7.5, textColor=colors.HexColor("#57606a"), alignment=1)

    content = []

    # ── Header ────────────────────────────────────────────────────────────
    content.append(Paragraph("SecureWipe", title_s))
    content.append(Paragraph("Certificate of Secure Data Destruction", sub_s))
    content.append(Paragraph(
        "Compliant with <b>NIST SP 800-88 Rev. 1</b> · Ed25519 Device-Attested · Signed PDF",
        sub_s))
    content.append(Spacer(1, 3*mm))
    content.append(HRFlowable(width="100%", thickness=2,
                               color=colors.HexColor("#0550ae")))
    content.append(Spacer(1, 3*mm))

    # ── Wipe summary + QR ─────────────────────────────────────────────────
    content.append(Paragraph("Wipe Summary", sec_s))
    summary = [
        ["Field", "Value"],
        ["Certificate ID",   cert_id],
        ["Date & Time",      timestamp.strftime("%Y-%m-%d  %H:%M:%S")],
        ["Algorithm",        algorithm],
        ["Overwrite Passes", str(passes)],
        ["Files Wiped",      str(len(wiped_files))],
        ["Status",           "SUCCESS — Data permanently destroyed"],
    ]
    # QR encodes the public key → scan to get it on phone
    qr_buf = io.BytesIO()
    _qr(pub_hex).save(qr_buf, "PNG")
    qr_buf.seek(0)
    rl_qr = RLImage(qr_buf, width=36*mm, height=36*mm)
    side = Table([[_tbl(summary, [50*mm, 88*mm]), rl_qr]],
                 colWidths=[142*mm, 38*mm])
    side.setStyle(TableStyle([
        ("VALIGN", (0,0),(-1,-1), "TOP"),
        ("LEFTPADDING",  (0,0),(-1,-1), 0),
        ("RIGHTPADDING", (0,0),(-1,-1), 0),
        ("TOPPADDING",   (0,0),(-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 0),
    ]))
    content.append(side)
    content.append(Paragraph(
        "↑ QR encodes the <b>Device Public Key</b> — scan to retrieve it.",
        sty("qqr", fontSize=7.5, textColor=colors.HexColor("#57606a"),
            spaceBefore=2, spaceAfter=6)))

    # ── Issuing Device ────────────────────────────────────────────────────
    content.append(Paragraph("Issuing Device", sec_s))
    content.append(Paragraph(
        "This certificate was issued from the device below. "
        "A verifier can cross-check these details against the physical hardware.",
        body_s))
    dev_rows = [
        ["Field", "Value"],
        ["Machine Name",   Paragraph(device_fp.get("machine_name", "—"), cell_s)],
        ["Windows User",   Paragraph(device_fp.get("username",     "—"), cell_s)],
        ["Machine GUID",   Paragraph(device_fp.get("machine_guid", "—"), mono_s)],
        ["MAC Address",    Paragraph(device_fp.get("mac_address",  "—"), cell_s)],
        ["Windows SID",    Paragraph(device_fp.get("windows_sid",  "—"), mono_s)],
        ["OS Version",     Paragraph(device_fp.get("os_version",   "—"), cell_s)],
    ]
    content.append(_tbl(dev_rows, [40*mm, 140*mm], small=True))

    # ── Storage Device (for full-drive wipes) ─────────────────────────────
    if storage_devices:
        content.append(Paragraph("Wiped Storage Devices", sec_s))
        content.append(Paragraph(
            "The following physical storage devices were identified during the wipe. "
            "A buyer can verify the serial number/model matches the device they received.",
            body_s))
        for drv in storage_devices:
            drv_rows = [
                ["Field", "Value"],
                ["Mount Point",  Paragraph(drv.get("mount_point", "—"), cell_s)],
                ["Model",        Paragraph(drv.get("model",       "—"), cell_s)],
                ["Serial No.",   Paragraph(drv.get("serial",      "—"), mono_s)],
                ["Filesystem",   Paragraph(drv.get("filesystem",  "—"), cell_s)],
                ["Capacity",     Paragraph(f"{drv.get('total_gb', 0):.2f} GB", cell_s)],
            ]
            content.append(_tbl(drv_rows, [38*mm, 142*mm], small=True))
            content.append(Spacer(1, 2*mm))

    # ── Destroyed file records ────────────────────────────────────────────
    content.append(Paragraph("Destroyed File Records", sec_s))
    # Use wider column for path, Paragraph for word wrap on all long values
    path_s = sty("Pa", fontSize=6.5, textColor=colors.HexColor("#24292f"),
                 leading=9, wordWrap='LTR')
    hash_s = sty("Ha", fontSize=6.5, fontName="Courier",
                 textColor=colors.HexColor("#24292f"), leading=9, wordWrap='LTR')
    rows = [["#", "File Name", "Original Path", "SHA-256  (pre-wipe)"]]
    for i, (path, sha) in enumerate(wiped_files.items(), start=1):
        rows.append([
            str(i),
            Paragraph(os.path.basename(path), path_s),
            Paragraph(path, path_s),
            Paragraph(sha[:32] + "<br/>" + sha[32:], hash_s),
        ])
    content.append(_tbl(rows, [7*mm, 40*mm, 80*mm, 53*mm], small=True))

    # ── Cryptographic proof + verification instructions ───────────────────
    content.append(Spacer(1, 3*mm))
    content.append(HRFlowable(width="100%", thickness=1,
                               color=colors.HexColor("#d0d7de")))
    content.append(Paragraph(
        "Cryptographic Proof  —  Verify at securewipe.app/verify", sec_s))
    content.append(Paragraph(
        "This <b>entire PDF document</b> (before the appended signature block) "
        "was hashed with SHA-256 and signed with Ed25519. "
        "Any modification to any part of this PDF — text, tables, or metadata — "
        "will produce a different hash and invalidate the signature.<br/><br/>"
        "To verify: upload this PDF and provide the public key below at "
        "<b>securewipe.app/verify</b> or open <b>verify.html</b> locally. "
        "Verification runs entirely in the browser — no internet, no server.",
        body_s))
    content.append(Spacer(1, 3*mm))

    pk_rows = [
        ["Device Public Key\n(Ed25519 · 32 bytes · 64 hex chars)",
         Paragraph(_chunk(pub_hex, 64), mono_s)],
    ]
    pk_tbl = Table(pk_rows, colWidths=[58*mm, 122*mm])
    pk_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(0,-1), colors.HexColor("#f6f8fa")),
        ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0),(-1,-1), 8.5),
        ("GRID",        (0,0),(-1,-1), 0.5, colors.HexColor("#d0d7de")),
        ("VALIGN",      (0,0),(-1,-1), "TOP"),
        ("LEFTPADDING", (0,0),(-1,-1), 8),
        ("TOPPADDING",  (0,0),(-1,-1), 7),
        ("BOTTOMPADDING",(0,0),(-1,-1), 7),
    ]))
    content.append(pk_tbl)
    content.append(Spacer(1, 3*mm))

    steps = [
        ["How to Verify", ""],
        ["Step 1", "Go to  securewipe.app/verify  (or open verify.html offline in Chrome/Firefox)"],
        ["Step 2", "Upload this PDF file"],
        ["Step 3", "Paste the Device Public Key above into the public key field"],
        ["Step 4", "Click Verify — browser hashes the PDF and runs Ed25519 math → ✅ or ❌"],
        ["No server", "Verification is pure cryptographic math. No internet needed. No account. No trust in us."],
    ]
    content.append(_tbl(steps, [28*mm, 152*mm], small=True))

    # ── Footer ────────────────────────────────────────────────────────────
    content.append(Spacer(1, 5*mm))
    content.append(HRFlowable(width="100%", thickness=0.5,
                               color=colors.HexColor("#d0d7de")))
    content.append(Spacer(1, 2*mm))
    content.append(Paragraph(
        f"SecureWipe v2.0  ·  NIST SP 800-88 Rev. 1  ·  Ed25519 (RFC 8032)  ·  "
        f"Cert ID: {cert_id}  ·  {timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        foot_s))

    doc.build(content)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _chunk(s: str, n: int) -> str:
    return "<br/>".join(s[i:i+n] for i in range(0, len(s), n))

def _qr(data: str):
    qr = qrcode.QRCode(version=None,
                       error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=6, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white")

def _tbl(data, col_widths, small=False):
    fs = 7.5 if small else 9
    t  = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), colors.HexColor("#0550ae")),
        ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), fs),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#d0d7de")),
        ("LEFTPADDING",   (0,0),(-1,-1), 7),
        ("RIGHTPADDING",  (0,0),(-1,-1), 7),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("FONTNAME",      (0,1),(0,-1), "Helvetica-Bold"),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
    ]))
    return t