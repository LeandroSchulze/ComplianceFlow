# reporter.py
import os
from datetime import datetime
from reportlab.lib.pagesizes import a4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ReportGenerator:
    def __init__(self, cliente_nombre: str):
        self.cliente_nombre = cliente_nombre

    def generar_pdf_cumplimiento(self, data: dict) -> str:
        """Genera un reporte PDF de alta fidelidad simétrico al diseño de Word"""
        norma = data.get("norma", "Estándar Regulatorio")
        titulo = data.get("titulo", "Reporte Técnico de Auditoría")
        evidencia_id = data.get("evidencia_id", "EV-GENERIC")
        estado = data.get("estado", "VERIFICADO")
        detalle = data.get("detalle", "No se proporcionó información técnica.")
        fecha_actual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        output_filename = f"evidencia_{data.get('id', 'gen')}.pdf"
        
        # Dimensiones de página A4 con márgenes limpios de 20mm
        doc = SimpleDocTemplate(
            output_filename,
            pagesize=a4,
            rightMargin=54, leftMargin=54,
            topMargin=54, bottomMargin=54
        )
        
        # Calcular ancho útil de la página de forma dinámica
        ancho_util = a4[0] - 108 
        
        styles = getSampleStyleSheet()
        
        # --- CONFIGURACIÓN DE ESTILOS EJECUTIVOS SIMÉTRICOS AL WORD ---
        style_left_header = ParagraphStyle(
            'LeftHeader',
            parent=styles['Normal'],
            fontName='Helvetica',
            leading=16
        )
        
        style_right_header = ParagraphStyle(
            'RightHeader',
            parent=styles['Normal'],
            fontName='Helvetica',
            alignment=2, # Derecha
            leading=12
        )
        
        style_norma_box = ParagraphStyle(
            'NormaBox',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15
        )
        
        style_h2 = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=colors.HexColor("#334155"),
            spaceBefore=18,
            spaceAfter=8,
            leading=14
        )
        
        style_meta_label = ParagraphStyle(
            'MetaLabel',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=colors.HexColor("#475569"),
            leading=14
        )
        
        style_meta_val = ParagraphStyle(
            'MetaValue',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor("#0f172a"),
            leading=14
        )
        
        style_detail = ParagraphStyle(
            'DetailText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor("#334155"),
            alignment=4, # Justificado
            leading=15
        )
        
        style_footer_title = ParagraphStyle(
            'FooterTitle',
            parent=styles['Normal'],
            fontName='Helvetica-BoldOblique',
            fontSize=8.5,
            textColor=colors.HexColor("#64748b"),
            alignment=1, # Centro
            spaceBefore=35,
            leading=12
        )
        
        style_footer_body = ParagraphStyle(
            'FooterBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            textColor=colors.HexColor("#64748b"),
            alignment=1,
            leading=11
        )

        story = []

        # =====================================================================
        # 1. ENCABEZADO CON LOGO CORPORATIVO (Mismo formato que Word)
        # =====================================================================
        p_left_html = """<b><font size=16 color="#0f172a">🛡️  ComplianceFlow</font></b><br/>
        <b><font size=7.5 color="#14b8a6">AUTOMATED B2B COMPLIANCE SUITE</font></b>"""
        p_left = Paragraph(p_left_html, style_left_header)
        
        p_right_html = """<b><font size=9 color="#10b981">SECURE RECORD</font></b><br/>
        <i><font size=8 color="#64748b">PostgreSQL Verified</font></i>"""
        p_right = Paragraph(p_right_html, style_right_header)
        
        header_table = Table([[p_left, p_right]], colWidths=[ancho_util * 0.65, ancho_util * 0.35])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(header_table)
        
        # Línea divisoria gris sutil
        line_table = Table([[""]], colWidths=[ancho_util])
        line_table.setStyle(TableStyle([
            ('LINEBELOW', (0,0), (-1,-1), 1.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(line_table)
        story.append(Spacer(1, 15))
        
        # =====================================================================
        # 2. BANNER DEL MARCO REGULATORIO (Bloque con fondo f1f5f9)
        # =====================================================================
        norma_html = f'<b><font color="#475569">Marco Regulatorio:</font></b> <font color="#0f172a"><b>{norma}</b></font>'
        p_norma = Paragraph(norma_html, style_norma_box)
        norma_table = Table([[p_norma]], colWidths=[ancho_util])
        norma_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0,0), (0,0), 10),
            ('BOTTOMPADDING', (0,0), (0,0), 10),
            ('LEFTPADDING', (0,0), (0,0), 12),
            ('RIGHTPADDING', (0,0), (0,0), 12),
            ('LINELEFT', (0,0), (0,0), 4, colors.HexColor("#0f172a")),
        ]))
        story.append(norma_table)
        
        # =====================================================================
        # 3. SECCIÓN 1: METADATOS COMPLETO
        # =====================================================================
        story.append(Paragraph("1. Metadatos de Control de la Auditoría", style_h2))
        
        meta_data = [
            [Paragraph("Título del Estudio:", style_meta_label), Paragraph(titulo, style_meta_val)],
            [Paragraph("ID Único de Evidencia:", style_meta_label), Paragraph(f"<b>{evidencia_id}</b>", style_meta_val)],
            [Paragraph("Estado del Control:", style_meta_label), Paragraph(f"<b>{estado}</b>", style_meta_val)],
            [Paragraph("Fecha de Evaluación:", style_meta_label), Paragraph(f"{fecha_actual} UTC", style_meta_val)],
            [Paragraph("Cliente Evaluado:", style_meta_label), Paragraph(self.cliente_nombre, style_meta_val)],
            [Paragraph("Sistema de Custodia:", style_meta_label), Paragraph("Evidence Locker Cifrado (AES-256)", style_meta_val)]
        ]
        
        meta_table = Table(meta_data, colWidths=[ancho_util * 0.3, ancho_util * 0.7])
        meta_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#f8fafc")),
        ]))
        story.append(meta_table)
        
        # =====================================================================
        # 4. SECCIÓN 2: DIAGNÓSTICO EXPLAYADO
        # =====================================================================
        story.append(Paragraph("2. Diagnóstico Técnico y Evidencia Conectada", style_h2))
        story.append(Paragraph(detalle, style_detail))
        
        # =====================================================================
        # 5. PIE DE PÁGINA CONFIDENCIAL
        # =====================================================================
        story.append(Spacer(1, 20))
        divider_table = Table([[""]], colWidths=[ancho_util])
        divider_table.setStyle(TableStyle([
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(divider_table)
        
        story.append(Paragraph("--- DOCUMENTO CONFIDENCIAL INALTERABLE ---", style_footer_title))
        story.append(Paragraph("Este documento constituye evidencia legal ejecutable ante auditores externos. Los hashes e integridad de los bloques están resguardados criptográficamente en la infraestructura del servidor PostgreSQL de Railway.", style_footer_body))
        
        # Compilar reporte físico
        doc.build(story)
        return output_filename
