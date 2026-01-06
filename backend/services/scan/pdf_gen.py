from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import io
import textwrap

def draw_header(c, width, height):
    c.setFillColor(colors.darkblue)
    c.rect(0, height - 80, width, 80, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 24)
    c.drawString(40, height - 50, "MalGuard Security Report")
    c.setFont("Helvetica", 12)
    c.drawString(40, height - 70, "Advanced Malware Analysis & Threat Detection")

def generate_pdf_report(data, filename="report.pdf"):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Header
    draw_header(c, width, height)

    y = height - 120
    c.setFillColor(colors.black)

    # File Info
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Target Analysis")
    y -= 25
    c.setFont("Helvetica", 12)
    
    meta = data.get('meta', {}).get('file_info', {}) # Adjust based on actual VT structure or passed data
    # If meta is empty, use top level keys if available (our local structure might vary)
    
    target_name = data.get('filename', 'Unknown File')
    target_id = data.get('id', 'N/A')
    
    c.drawString(50, y, f"Filename: {target_name}")
    y -= 20
    c.drawString(50, y, f"ID/Hash: {target_id}")
    y -= 40

    # Threat Score
    stats = data.get('data', {}).get('stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    total = malicious + suspicious + harmless + undetected

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Threat Summary")
    y -= 30

    # Draw Risk Badge (Simulated)
    risk_color = colors.green
    risk_text = "SAFE"
    if malicious > 0:
        risk_color = colors.red
        risk_text = "CRITICAL THREAT"
    elif suspicious > 0:
        risk_color = colors.orange
        risk_text = "SUSPICIOUS"

    c.setFillColor(risk_color)
    c.rect(50, y - 15, 150, 30, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(65, y - 5, f"STATUS: {risk_text}")
    
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 12)
    y -= 50
    c.drawString(50, y, f"Malicious Detections: {malicious} / {total}")
    y -= 20
    c.drawString(50, y, f"Suspicious: {suspicious}")
    y -= 20
    c.drawString(50, y, f"Clean/Undetected: {harmless + undetected}")
    y -= 40

    # Engine Details
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Engine Detections")
    y -= 25
    c.setFont("Helvetica", 10)

    results = data.get('data', {}).get('results', {})
    
    # Filter for non-safe first
    detections = []
    for engine, res in results.items():
        if res.get('category') in ['malicious', 'suspicious']:
            detections.append((engine, res))
    
    if not detections:
        c.drawString(50, y, "No security vendors flagged this file as malicious.")
    else:
        c.drawString(50, y, f"Found {len(detections)} threats from security vendors:")
        y -= 20
        for engine, res in detections[:20]: # Limit to 20 to fit page
            cat = res.get('category').upper()
            result_name = res.get('result', 'Detected')
            text = f"- {engine}: {result_name} [{cat}]"
            
            if y < 50: # New Page needed
                c.showPage()
                draw_header(c, width, height)
                y = height - 120
                c.setFont("Helvetica", 10)
            
            if cat == 'MALICIOUS':
                c.setFillColor(colors.red)
            else:
                c.setFillColor(colors.orange)
            
            c.drawString(60, y, text)
            c.setFillColor(colors.black)
            y -= 15

    c.save()
    buffer.seek(0)
    return buffer
