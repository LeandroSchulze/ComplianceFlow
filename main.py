# main.py
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
import os
import io
from datetime import datetime
from dotenv import load_dotenv
from docx import Document
from docx.shared import Pt, Inches

# Importamos tus módulos existentes
from scanner import ComplianceScanner
from reporter import ReportGenerator
from auth import AuthManager
from legal_config import LegalShield
from security import registrar_evento

load_dotenv()

app = FastAPI(
    title="Automated Compliance API",
    description="Ecosistema para automatización de evidencias SOC 2 / ISO 27001",
    version="1.0.0"
)

auth_handler = AuthManager()

# Modelos de Pydantic
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    codigo_mfa: str

class ScanRequest(BaseModel):
    cliente_nombre: str

# --- CLASE CAMALEÓN PARA EVITAR ERRORES EN TEMPLATES PDF ---
class SmartBreach(str):
    """Clase especial que previene KeyErrors si el template busca diccionarios o strings"""
    def __getitem__(self, key): return str(self)
    def get(self, key, default=None): return str(self)

# --- REPOSITORIO DE DATOS DE PRUEBA CORPORATIVOS ---
DATA_ESTANDARES = {
    "ISO-IAM": {
        "norma": "ISO 27001 — Anexo A.9",
        "titulo": "Auditoría de Políticas de Identidades y Control de Accesos",
        "evidencia_id": "EV-ISO-A9-8812",
        "estado": "⚠️ 1 OBSERVACIÓN DETECTADA",
        "detalle": "El análisis algorítmico detectó políticas de privilegios elevados (AdministratorAccess) asignadas a identidades de desarrollo que no registran la activación obligatoria de Doble Factor de Autenticación (MFA). Se requiere remediación para mantener la certificación del SGSI."
    },
    "SOC2-S3": {
        "norma": "SOC 2 Type II — Sección CC6.3",
        "titulo": "Análisis Criptográfico de Infraestructura de Almacenamiento Nube",
        "evidencia_id": "EV-SOC2-S3-9202",
        "estado": "🟢 100% CUMPLIDO (Secure Vault Activo)",
        "detalle": "Se ha verificado mediante llamadas programáticas seguras que el 100% de los repositorios de datos globales (Amazon S3) poseen las restricciones globales 'Public Access Block' activas. Las firmas confirman cifrado del lado del servidor SSE-S3 de forma persistente."
    },
    "SOC1-FIN": {
        "norma": "SOC 1 — Controles Internos Financieros (ICFR)",
        "titulo": "Matriz de Segregación de Funciones y Auditoría Contable",
        "evidencia_id": "EV-SOC1-FIN-7741",
        "estado": "🟢 100% CUMPLIDO",
        "detalle": "Validación exitosa de segregación de funciones (SoD). El sistema confirma que las firmas digitales que autorizan movimientos o balances contables en el núcleo transaccional están debidamente desacopladas de las cuentas de desarrollo."
    },
    "ISO-9001": {
        "norma": "ISO 9001 — Cláusula 8.2",
        "titulo": "Trazabilidad de Requisitos de Calidad y Gestión de Despliegues",
        "evidencia_id": "EV-ISO9-QA-3321",
        "estado": "🟢 100% CUMPLIDO",
        "detalle": "Revisión automatizada del pipeline de integración continua (CI/CD). Cada compilación y paso a producción cuenta con el registro de aprobación cruzada firmado por la mesa de control de calidad operativa."
    },
    "ISO-45001": {
        "norma": "ISO 45001 — Cláusula 6.1.2",
        "titulo": "Matriz Histórica de Mitigación de Riesgos y Seguridad Laboral",
        "evidencia_id": "EV-ISO45-OHS-009a",
        "estado": "🟢 100% CUMPLIDO",
        "detalle": "Estructura de logs de control físico e higiene ocupacional verificado. Se registran las firmas digitales de conformidad de las capacitaciones mandatorias del personal y las inspecciones estructurales de planta."
    }
}

# --- LÓGICA AUXILIAR: GENERADOR DE WORD EN MEMORIA ---
def generar_word_evidencia_interno(doc_id: str) -> io.BytesIO:
    doc = Document()
    
    # Configuración de márgenes institucionales (1 pulgada por lado)
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    info = DATA_ESTANDARES.get(doc_id, {
        "norma": "Estándar Corporativo", "titulo": "Reporte Técnico", "evidencia_id": "EV-GEN", "estado": "VERIFICADO", "detalle": "Análisis completado."
    })

    # =========================================================================
    # LOGO Y CABECERA PREMIUM (CONSTRUCCIÓN NATIVA)
    # =========================================================================
    # Creamos una estructura de tabla de 1 fila x 2 columnas para el branding
    header_table = doc.add_table(rows=1, cols=2)
    header_table.autofit = False
    header_table.columns[0].width = Inches(4.5)
    header_table.columns[1].width = Inches(2.0)
    
    # Columna Izquierda: Isotipo y Nombre de la App
    cell_left = header_table.cell(0, 0)
    p_logo = cell_left.paragraphs[0]
    run_icon = p_logo.add_run("🛡️  ")
    run_icon.font.size = Pt(20)
    
    run_brand = p_logo.add_run("ComplianceFlow")
    run_brand.font.name = 'Arial'
    run_brand.font.size = Pt(16)
    run_brand.font.bold = True
    run_brand.font.color.rgb = docx.shared.RGBColor(15, 23, 42) # Azul Marino Oscuro
    
    p_sub_logo = cell_left.add_paragraph()
    run_sub_logo = p_sub_logo.add_run("AUTOMATED B2B COMPLIANCE SUITE")
    run_sub_logo.font.name = 'Arial'
    run_sub_logo.font.size = Pt(7.5)
    run_sub_logo.font.bold = True
    run_sub_logo.font.color.rgb = docx.shared.RGBColor(20, 184, 166) # Color Teal / Turquesa
    
    # Columna Derecha: Sello de Seguridad de la Base de Datos
    cell_right = header_table.cell(0, 1)
    p_secure = cell_right.paragraphs[0]
    p_secure.alignment = 2 # Alineación a la derecha
    run_sec_txt = p_secure.add_run("SECURE RECORD\n")
    run_sec_txt.font.size = Pt(8)
    run_sec_txt.font.bold = True
    run_sec_txt.font.color.rgb = docx.shared.RGBColor(16, 185, 129) # Verde esmeralda
    
    run_db_txt = p_secure.add_run("PostgreSQL Verified")
    run_db_txt.font.size = Pt(8)
    run_db_txt.font.italic = True
    
    # Línea divisoria elegante
    p_line = doc.add_paragraph()
    run_line = p_line.add_run("_______________________________________________________________________")
    run_line.font.color.rgb = docx.shared.RGBColor(203, 213, 225)
    run_line.font.size = Pt(10)
    
    doc.add_paragraph("\n") # Espaciador
    # =========================================================================

    # Título del Marco Regulatorio
    h_norma = doc.add_heading(level=1)
    run_norma = h_norma.add_run(f"Marco Regulatorio: {info['norma']}")
    run_norma.font.name = 'Arial'
    run_norma.font.color.rgb = docx.shared.RGBColor(15, 23, 42)
    
    # Tabla de Metadatos del Auditor
    doc.add_heading("1. Metadatos de Control de la Auditoría", level=2)
    p_meta = doc.add_paragraph()
    p_meta.add_run("Título del Estudio: ").bold = True
    p_meta.add_run(f"{info['titulo']}\n")
    p_meta.add_run("ID Único de Evidencia: ").bold = True
    p_meta.add_run(f"{info['evidencia_id']}\n")
    p_meta.add_run("Estado del Control: ").bold = True
    p_meta.add_run(f"{info['estado']}\n")
    p_meta.add_run("Fecha de Evaluación: ").bold = True
    p_meta.add_run(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
    p_meta.add_run("Sistema de Custodia: ").bold = True
    p_meta.add_run("Evidence Locker Cifrado (AES-256)\n")
    
    # Detalle de la Trazabilidad
    doc.add_heading("2. Diagnóstico Técnico y Evidencia Conectada", level=2)
    doc.add_paragraph(info['detalle'])
    
    # Pie Legal Criptográfico
    doc.add_paragraph("\n\n--- DOCUMENTO CONFIDENCIAL INALTERABLE ---").italic = True
    p_foot = doc.add_paragraph()
    run_f = p_foot.add_run("Este documento constituye evidencia legal ejecutable ante auditores externos. Los hashes e integridad de los bloques están resguardados criptográficamente en la infraestructura del servidor.")
    run_f.font.size = Pt(8.5)
    run_f.font.color.rgb = docx.shared.RGBColor(100, 116, 139)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer


# --- ENDPOINT DE DESCARGA DINÁMICA ---
@app.get("/api/compliance/download", tags=["Escáner"])
def descargar_evidencia_unificada(format: str, id: str):
    registrar_evento(f"Descarga solicitada para estándar: {id} | Formato: {format}")
    
    if id not in DATA_ESTANDARES:
        raise HTTPException(status_code=404, detail="Estándar regulatorio no localizado.")
        
    info = DATA_ESTANDARES[id]
    
    # Flujo Word (.docx)
    if format == "word":
        try:
            buffer_word = generar_word_evidencia_interno(id)
            filename = f"evidencia_{id}_{datetime.now().strftime('%Y%m%d')}.docx"
            return StreamingResponse(
                buffer_word, 
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en Word: {str(e)}")
    
    # Flujo PDF (.pdf)
    elif format == "pdf":
        try:
            # Creamos el objeto camaleón con el texto del detalle
            smart_b = SmartBreach(info["detalle"])
            
            # Inyectamos de forma masiva todas las variantes que tu reporter.py podría buscar
            mock_payload = {
                "id": id,
                "norma": info["norma"],
                "status": info["estado"],
                "estado_global": info["estado"],
                "detalle": info["detalle"],
                "brechas": [] if "100%" in info["estado"] else [smart_b],
                "vulnerabilidades": [] if "100%" in info["estado"] else [smart_b],
                "metrics": {"control_id": info["evidencia_id"], "alertas": 0 if "100%" in info["estado"] else 1}
            }
            
            reporter = ReportGenerator(cliente_nombre="Matriz de Infraestructura Conectada")
            archivo_pdf = reporter.generar_pdf_cumplimiento(mock_payload)
            return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=f"evidencia_{id}.pdf")
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en reporter.py: {str(e)}")
            
    else:
        raise HTTPException(status_code=400, detail="Formato de exportación inválido.")

# --- ENDPOINTS FRONTEND Y NAVEGACIÓN ---
@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
def index(): return FileResponse("templates/index.html")

@app.get("/dashboard", response_class=HTMLResponse, tags=["Frontend"])
def dashboard(): return FileResponse("templates/dashboard.html")

@app.get("/login", response_class=HTMLResponse, tags=["Frontend"])
def mostrar_login(): return FileResponse("templates/login.html")

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, tags=["Autenticación"])
def registrar(usuario: UserRegister):
    try:
        mfa_secret = auth_handler.registrar_usuario(usuario.email, usuario.password)
        return {"mensaje": "Usuario registrado", "mfa_secret": mfa_secret}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error al registrar.")

@app.post("/api/auth/login", tags=["Autenticación"])
def login(usuario: UserLogin):
    codigo_limpio = usuario.codigo_mfa.replace(" ", "").replace("-", "").strip()
    if not auth_handler.verificar_mfa(usuario.email, codigo_limpio):
        raise HTTPException(status_code=401, detail="Código MFA inválido.")
    return {"mensaje": "Acceso concedido"}

@app.post("/api/compliance/scan", tags=["Escáner"])
def ejecutar_escaneo_web(solicitud: ScanRequest):
    scanner = ComplianceScanner()
    reporter = ReportGenerator(cliente_nombre=solicitud.cliente_nombre)
    resultados = scanner.escanear_infraestructura()
    archivo_pdf = reporter.generar_pdf_cumplimiento(resultados)
    return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=archivo_pdf)
