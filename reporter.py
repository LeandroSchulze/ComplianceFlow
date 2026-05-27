from fpdf import FPDF
from datetime import datetime
from security import registrar_evento

class ReportGenerator:
    def __init__(self, cliente_nombre):
        self.cliente = cliente_nombre
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)

    def generar_pdf_cumplimiento(self, resultados_escaneo):
        """Genera el reporte que sirve como Lead Magnet (Gancho)"""
        self.pdf.add_page()
        
        # Encabezado Corporativo (Requerimiento 4.1)
        self.pdf.set_font("Arial", 'B', 16)
        self.pdf.cell(200, 10, txt="Reporte de Brechas de Cumplimiento (Automated Compliance)", ln=True, align='C')
        
        self.pdf.set_font("Arial", size=12)
        self.pdf.ln(10)
        self.pdf.cell(200, 10, txt=f"Cliente: {self.cliente}", ln=True)
        self.pdf.cell(200, 10, txt=f"Fecha de Auditoría: {datetime.now().strftime('%d/%m/%Y')}", ln=True)
        self.pdf.ln(10)

        # Resumen de Hallazgos
        self.pdf.set_font("Arial", 'B', 12)
        self.pdf.cell(200, 10, txt="Hallazgos Críticos detectados:", ln=True)
        self.pdf.set_font("Arial", size=10)

        if not resultados_escaneo["brechas"]:
            self.pdf.cell(200, 10, txt="No se detectaron brechas críticas. ¡Buen trabajo!", ln=True)
        else:
            for brecha in resultados_escaneo["brechas"]:
                self.pdf.multi_cell(0, 10, txt=f"- [{brecha['prioridad']}] Recurso: {brecha['recurso']} | Error: {brecha['error']}")

        # Pie de página con Blindaje Legal (Requerimiento 3.1)
        self.pdf.ln(20)
        self.pdf.set_font("Arial", 'I', 8)
        nota_legal = ("Limitación de Responsabilidad: Este reporte es una herramienta de asistencia. "
                      "La decisión final de cumplimiento recae en el cliente o su auditor certificado.")
        self.pdf.multi_cell(0, 5, txt=nota_legal)

        filename = f"reporte_compliance_{self.cliente}.pdf"
        self.pdf.output(filename)
        registrar_evento(f"Reporte generado para {self.cliente}")
        return filename
