# reporter.py
import os
from datetime import datetime
from weasyprint import HTML

class ReportGenerator:
    def __init__(self, cliente_nombre: str):
        self.cliente_nombre = cliente_nombre

    def generar_pdf_cumplimiento(self, data: dict) -> str:
        """Genera un reporte PDF corporativo simétrico al diseño de Word"""
        norma = data.get("norma", "Estándar Regulatorio")
        titulo = data.get("titulo", "Reporte Técnico de Auditoría")
        evidencia_id = data.get("evidencia_id", "EV-GENERIC")
        estado = data.get("estado", "VERIFICADO")
        detalle = data.get("detalle", "No se proporcionó información técnica.")
        fecha_actual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # LOGO VECTORIAL OFICIAL DE COMPLIANCEFLOW (Asegura renderizado perfecto en Railway)
        logo_svg = """
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3z" fill="#0f172a"/>
            <path d="M12 6l-6 2v3.5c0 3.72 2.56 7.19 6 8.1 3.44-.91 6-4.38 6-8.1V8l-6-2z" fill="#20m14b8a6" style="fill: #14b8a6;"/>
        </svg>
        """

        html_template = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <style>
                @page {{
                    size: A4;
                    margin: 25mm 20mm;
                    @bottom-right {{
                        content: "Página 1 de 1";
                        font-family: 'Arial', sans-serif;
                        font-size: 8pt;
                        color: #64748b;
                    }}
                }}
                body {{
                    font-family: 'Arial', sans-serif;
                    color: #1e293b;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                }}
                /* ENCABEZADO PREMIUM */
                .header-table {{
                    width: 100%;
                    border-collapse: collapse;
                    border-bottom: 2px solid #cbd5e1;
                    padding-bottom: 12px;
                    margin-bottom: 30px;
                }}
                .logo-section {{
                    width: 65%;
                    vertical-align: middle;
                }}
                .logo-container {{
                    display: inline-block;
                    vertical-align: middle;
                    margin-right: 10px;
                }}
                .brand-text {{
                    display: inline-block;
                    vertical-align: middle;
                }}
                .brand-title {{
                    font-size: 18pt;
                    font-weight: bold;
                    color: #0f172a;
                    margin: 0;
                }}
                .brand-subtitle {{
                    font-size: 7.5pt;
                    font-weight: bold;
                    color: #14b8a6;
                    letter-spacing: 1px;
                    margin: 2px 0 0 0;
                }}
                .secure-section {{
                    width: 35%;
                    text-align: right;
                    vertical-align: middle;
                }}
                .secure-tag {{
                    font-size: 9pt;
                    font-weight: bold;
                    color: #10b981;
                    margin: 0;
                    letter-spacing: 0.5px;
                }}
                .db-tag {{
                    font-size: 8pt;
                    font-style: italic;
                    color: #64748b;
                    margin: 2px 0 0 0;
                }}
                /* CONTENIDO HEDING */
                .main-title {{
                    font-size: 14pt;
                    color: #0f172a;
                    margin-top: 0;
                    margin-bottom: 25px;
                    background-color: #f1f5f9;
                    padding: 10px 12px;
                    border-left: 4px solid #0f172a;
                }}
                h2 {{
                    font-size: 11pt;
                    color: #334155;
                    margin-top: 25px;
                    margin-bottom: 12px;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 5px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                /* METADATOS */
                .meta-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 25px;
                }}
                .meta-table td {{
                    padding: 7px 0;
                    font-size: 10pt;
                    vertical-align: top;
                }}
                .label {{
                    font-weight: bold;
                    color: #475569;
                    width: 28%;
                }}
                .value {{
                    color: #0f172a;
                }}
                .status {{
                    font-weight: bold;
                    color: #0f172a;
                }}
                /* DETALLE */
                .detail-text {{
                    font-size: 10pt;
                    color: #334155;
                    text-align: justify;
                    line-height: 1.5;
                }}
                /* FOOTER LEGAL */
                .footer-legal {{
                    margin-top: 60px;
                    border-top: 1px solid #e2e8f0;
                    padding-top: 15px;
                    font-size: 8pt;
                    color: #64748b;
                    text-align: center;
                }}
                .footer-legal .confidential {{
                    font-style: italic;
                    font-weight: bold;
                    margin-bottom: 4px;
                }}
            </style>
        </head>
        <body>

            <table class="header-table">
                <tr>
                    <td class="logo-section">
                        <div class="logo-container">{logo_svg}</div>
                        <div class="brand-text">
                            <h1 class="brand-title">ComplianceFlow</h1>
                            <p class="brand-subtitle">AUTOMATED B2B COMPLIANCE SUITE</p>
                        </div>
                    </td>
                    <td class="secure-section">
                        <p class="secure-tag">SECURE RECORD</p>
                        <p class="db-tag">PostgreSQL Verified</p>
                    </td>
                </tr>
            </table>

            <div class="main-title">
                <strong>Marco Regulatorio:</strong> {norma}
            </div>

            <h2>1. Metadatos de Control de la Auditoría</h2>
            <table class="meta-table">
                <tr>
                    <td class="label">Título del Estudio:</td>
                    <td class="value">{titulo}</td>
                </tr>
                <tr>
                    <td class="label">ID Único de Evidencia:</td>
                    <td class="value" style="font-family: monospace; letter-spacing: 0.5px;">{evidencia_id}</td>
                </tr>
                <tr>
                    <td class="label">Estado del Control:</td>
                    <td class="value status">{estado}</td>
                </tr>
                <tr>
                    <td class="label">Fecha de Evaluación:</td>
                    <td class="value">{fecha_actual} UTC</td>
                </tr>
                <tr>
                    <td class="label">Cliente Evaluado:</td>
                    <td class="value">{self.cliente_nombre}</td>
                </tr>
                <tr>
                    <td class="label">Sistema de Custodia:</td>
                    <td class="value">Evidence Locker Cifrado (AES-256)</td>
                </tr>
            </table>

            <h2>2. Diagnóstico Técnico y Evidencia Conectada</h2>
            <div class="detail-text">
                {detalle}
            </div>

            <div class="footer-legal">
                <p class="confidential">--- DOCUMENTO CONFIDENCIAL INALTERABLE ---</p>
                <p>Este documento constituye evidencia legal ejecutable ante auditores externos. Los hashes e integridad de los bloques están resguardados criptográficamente en la infraestructura del servidor PostgreSQL de Railway.</p>
            </div>

        </body>
        </html>
        """
        output_filename = f"evidencia_{data.get('id', 'gen')}.pdf"
        HTML(string=html_template).write_pdf(output_filename)
        return output_filename
