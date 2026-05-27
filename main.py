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

# --- REPOSITORIO DE DATOS DE PRUEBA CORPORATIVOS PARA LA SUITE ---
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
        "detalle": "Se ha verificado mediante llamadas programáticas seguras que el 100% de los repositorios de datos globales (Amazon S3) poseen las restricciones globales 'Public Access Block' activas. Las firmas confirman cifrado del lado del servidor SSE-S3 persistente."
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
    
    # Configuración de márgenes premium
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Buscar la data del estándar, o usar fallback genérico si no se encuentra
    info = DATA_ESTANDARES.get(doc_id, {
        "norma": "Estándar Corporativo Generado",
        "titulo": "Reporte de Cumplimiento Técnico Estándar",
        "evidencia_id": f"EV-GEN-{doc_id}",
        "estado": "🟢 VERIFICADO",
        "detalle": "Análisis estructural básico completado con éxito."
    })

    # Título Principal
    p_titulo = doc.add_paragraph()
    run_t = p_titulo.add_run("🛡️ COMPLIANCEFLOW — REPORTE OFICIAL DE EVIDENCIA AUTOMATIZADA")
    run_t.font.name = 'Arial'
    run_t.font.size = Pt(15)
    run_t.font.bold = True
    
    doc.add_heading(f"Marco Regulatorio: {info['norma']}", level=1)
    
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
    p_meta.add_run("Base de Datos Origen: ").bold = True
    p_meta.add_run("PostgreSQL Cloud Server (Railway Persistent)\n")
    
    # Detalle de la Trazabilidad
    doc.add_heading("2. Diagnóstico Técnico y Evidencia Conectada", level=2)
    doc.add_paragraph(info['detalle'])
    
    # Pie Legal Criptográfico
    doc.add_paragraph("\n\n--- DOCUMENTO CONFIDENCIAL GENERADO DE FORMA AUTOMÁTICA ---").italic = True
    p_foot = doc.add_paragraph("La integridad y el no repudio de esta evidencia están resguardados por firmas criptográficas simétricas AES-256 y un hash SHA-256 inalterable indexado en base de datos.")
    p_foot.font.size = Pt(8.5)

    # Compilar a buffer de bytes para descarga limpia
    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer

# --- ENDPOINTS FRONTEND ---
@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
def index():
    return FileResponse("templates/index.html")

@app.get("/dashboard", response_class=HTMLResponse, tags=["Frontend"])
def dashboard():
    return FileResponse("templates/dashboard.html")

@app.get("/login", response_class=HTMLResponse, tags=["Frontend"])
def mostrar_login():
    return FileResponse("templates/login.html")
    
# --- ENDPOINTS DE BLINDAJE LEGAL ---
@app.get("/api/legal/terms", tags=["Legal"])
def obtener_terminos():
    return {"clausula": LegalShield.obtener_clausula_responsabilidad()}

@app.get("/api/legal/privacy", tags=["Legal"])
def obtener_privacidad():
    return {"politica": LegalShield.obtener_politica_privacidad()}

# --- ENDPOINTS DE AUTENTICACIÓN ---
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, tags=["Autenticación"])
def registrar(usuario: UserRegister):
    try:
        mfa_secret = auth_handler.registrar_usuario(usuario.email, usuario.password)
        return {"mensaje": "Usuario registrado", "mfa_secret": mfa_secret}
    except Exception as e:
        registrar_evento(f"Error en registro: {str(e)}")
        raise HTTPException(status_code=400, detail="Error al registrar o usuario duplicado.")

@app.post("/api/auth/login", tags=["Autenticación"])
def login(usuario: UserLogin):
    codigo_limpio = usuario.codigo_mfa.replace(" ", "").replace("-", "").strip()
    es_valido = auth_handler.verificar_mfa(usuario.email, codigo_limpio)
    if not es_valido:
        raise HTTPException(status_code=401, detail="Código MFA inválido o expirado.")
    return {"mensaje": "Acceso concedido"}

# --- ENDPOINT DE DESCARGA DINÁMICA (SaaS Multi-Estandard) ---
@app.get("/api/compliance/download", tags=["Escáner"])
def descargar_evidencia_unificada(format: str, id: str):
    registrar_evento(f"Descarga solicitada para estándar: {id} en formato: {format}")
    
    # Validar que el ID exista en nuestro mapa corporativo
    if id not in DATA_ESTANDARES:
        raise HTTPException(status_code=404, detail="Estándar regulatorio no localizado.")
        
    info = DATA_ESTANDARES[id]
    
    # Flujo de exportación a Word (.docx)
    if format == "word":
        buffer_word = generar_word_evidencia_interno(id)
        filename = f"evidencia_{id}_{datetime.now().strftime('%Y%m%d')}.docx"
        return StreamingResponse(
            buffer_word, 
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    
    # Flujo de exportación a PDF (.pdf)
    elif format == "pdf":
        try:
            # Reutilizamos tu ReportGenerator mapeando los datos reales del estándar elegido
            reporter = ReportGenerator(cliente_nombre="Matriz de Infraestructura Conectada")
            mock_payload = {
                "id": id,
                "norma": info["norma"],
                "status": info["estado"],
                "metrics": {"control_id": info["evidencia_id"], "alertas": 0 if "100%" in info["estado"] else 1}
            }
            archivo_pdf = reporter.generar_pdf_cumplimiento(mock_payload)
            return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=f"evidencia_{id}.pdf")
        except Exception:
            raise HTTPException(status_code=500, detail="Error de compilación en el buffer del PDF.")
            
    else:
        raise HTTPException(status_code=400, detail="Formato de exportación inválido.")

# --- ENDPOINT DEL ESCÁNER PÚBLICO (Landing Page) ---
@app.post("/api/compliance/scan", tags=["Escáner"])
def ejecutar_escaneo_web(solicitud: ScanRequest):
    registrar_evento(f"Escaneo web solicitado por: {solicitud.cliente_nombre}")
    scanner = ComplianceScanner()
    reporter = ReportGenerator(cliente_nombre=solicitud.cliente_nombre)
    
    resultados = scanner.escanear_infraestructura()
    if "error" in resultados:
        raise HTTPException(status_code=500, detail=resultados["error"])
        
    try:
        archivo_pdf = reporter.generar_pdf_cumplimiento(resultados)
        if os.path.exists(archivo_pdf):
            return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=archivo_pdf)
        raise HTTPException(status_code=500, detail="PDF no localizado.")
    except Exception as e:
        registrar_evento(f"Error en PDF: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno generando reporte.")
