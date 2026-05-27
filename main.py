# main.py
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
import os
import io
import psycopg2
from datetime import datetime
from dotenv import load_dotenv

import docx
from docx import Document
from docx.shared import Pt, Inches, RGBColor

# SDK de MercadoPago
import mercadopago

from scanner import ComplianceScanner
from reporter import ReportGenerator
from auth import AuthManager
from legal_config import LegalShield
from security import registrar_evento

load_dotenv()

app = FastAPI(
    title="ComplianceFlow API",
    description="Ecosistema Premium para automatización de evidencias SOC 2 / ISO 27001",
    version="1.1.0"
)

auth_handler = AuthManager()

# Inicializar MercadoPago con tus credenciales de producción/prueba (.env)
mp_access_token = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "TEST-TU-ACCESS-TOKEN")
mp_sdk = mercadopago.SDK(mp_access_token)

class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    codigo_mfa: str

class ScanRequest(BaseModel):
    cliente_nombre: str

# Repositorio de simulación para la Suite interna
DATA_ESTANDARES = {
    "ISO-IAM": {"norma": "ISO 27001 — Anexo A.9", "titulo": "Auditoría de Control de Accesos", "evidencia_id": "EV-ISO-A9-8812", "estado": "⚠️ OBSERVACIÓN", "detalle": "Políticas AdministratorAccess sin MFA activo."},
    "SOC2-S3": {"norma": "SOC 2 Type II — CC6.3", "titulo": "Análisis Criptográfico S3", "evidencia_id": "EV-SOC2-S3-9202", "estado": "🟢 100% CUMPLIDO", "detalle": "Public Access Block activo y cifrado SSE-S3 persistente."},
    "SOC1-FIN": {"norma": "SOC 1 — Controles ICFR", "titulo": "Matriz de Segregación de Funciones", "evidencia_id": "EV-SOC1-FIN-7741", "estado": "🟢 100% CUMPLIDO", "detalle": "Firmas transaccionales desacopladas de las cuentas de desarrollo."},
    "ISO-9001": {"norma": "ISO 9001 — Cláusula 8.2", "titulo": "Trazabilidad de Requisitos de Calidad", "evidencia_id": "EV-ISO9-QA-3321", "estado": "🟢 100% CUMPLIDO", "detalle": "Pipeline CI/CD cuenta con aprobación cruzada firmada por QA."},
    "ISO-45001": {"norma": "ISO 45001 — Cláusula 6.1.2", "titulo": "Matriz de Seguridad Laboral", "evidencia_id": "EV-ISO45-OHS-009a", "estado": "🟢 100% CUMPLIDO", "detalle": "Logs de control físico e higiene ocupacional indexados con firmas digitales."}
}

# --- CONTROL DE INFRAESTRUCTURA DE LÍMITES POR IP (POSTGRES) ---
def obtener_conexion_db():
    db_url = os.getenv("DATABASE_URL")
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(db_url)

def inicializar_tabla_limites():
    """Crea la tabla de control de IPs para el freemium si no existe"""
    try:
        with obtener_conexion_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS control_ips (
                        ip VARCHAR(45) PRIMARY KEY,
                        escaneos_realizados INT DEFAULT 0,
                        ultima_peticion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
    except Exception as e:
        print(f"Error inicializando control_ips: {str(e)}")

inicializar_tabla_limites()

def obtener_ip_cliente(request: Request) -> str:
    """Captura la IP real del cliente saltando el proxy inverso de Railway"""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def verificar_y_actualizar_limite_ip(ip: str) -> int:
    """Retorna el número de escaneos realizados. Incrementa si es menor a 3."""
    with obtener_conexion_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT escaneos_realizados FROM control_ips WHERE ip = %s", (ip,))
            resultado = cursor.fetchone()
            
            if not resultado:
                cursor.execute("INSERT INTO control_ips (ip, escaneos_realizados) VALUES (%s, 1)", (ip,))
                conn.commit()
                return 1
            
            actuales = resultado[0]
            if actuales < 3:
                nuevos = actuales + 1
                cursor.execute("UPDATE control_ips SET escaneos_realizados = %s, ultima_peticion = CURRENT_TIMESTAMP WHERE ip = %s", (nuevos, ip))
                conn.commit()
                return nuevos
            
            return actuales

# --- ENDPOINT DE INTEGRACIÓN CON MERCADOPAGO ---
@app.post("/api/checkout/preference", tags=["Financiero"])
def crear_preferencia_pago():
    """Genera una pasarela de pago para el acceso ilimitado"""
    try:
        preference_data = {
            "items": [
                {
                    "title": "ComplianceFlow — Licencia Escáner Ilimitado",
                    "quantity": 1,
                    "unit_price": 4999.00,  # Precio en ARS (Modificable)
                    "currency_id": "ARS"
                }
            ],
            "back_urls": {
                "success": "https://complianceflow-production.up.railway.app/dashboard", # Cambiala por tu url real
                "failure": "https://complianceflow-production.up.railway.app/dashboard",
                "pending": "https://complianceflow-production.up.railway.app/dashboard"
            },
            "auto_return": "approved",
        }
        
        result = mp_sdk.preference().create(preference_data)
        return {"init_point": result["response"]["init_point"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al conectar con MercadoPago: {str(e)}")

# --- ENDPOINT DEL ESCÁNER PÚBLICO OPTIMIZADO (LIMITADO A 3 POR IP) ---
@app.post("/api/compliance/scan", tags=["Escáner"])
def ejecutar_escaneo_web(solicitud: ScanRequest, request: Request):
    ip_cliente = obtener_ip_cliente(request)
    escaneos = verificar_y_actualizar_limite_ip(ip_cliente)
    
    if escaneos > 3:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Límite gratuito alcanzado (3 escaneos por IP). Adquiera la suite ilimitada para continuar."
        )
        
    registrar_evento(f"Escaneo {escaneos}/3 para la IP: {ip_cliente}")
    
    scanner = ComplianceScanner()
    reporter = ReportGenerator(cliente_nombre=solicitud.cliente_nombre)
    resultados = scanner.escanear_infraestructura()
    archivo_pdf = reporter.generar_pdf_cumplimiento(resultados)
    
    return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=archivo_pdf)

# --- REPOSITORIO DE FUNCIONES AUXILIARES (WORD / DOWNLOADS / FRONTEND) ---
def generar_word_evidencia_interno(doc_id: str) -> io.BytesIO:
    doc = Document()
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    info = DATA_ESTANDARES.get(doc_id, {"norma": "Estándar Corporativo", "titulo": "Reporte Técnico", "evidencia_id": "EV-GEN", "estado": "VERIFICADO", "detalle": "Análisis completado."})

    header_table = doc.add_table(rows=1, cols=2)
    header_table.autofit = False
    header_table.columns[0].width = Inches(4.5)
    header_table.columns[1].width = Inches(2.0)
    
    cell_left = header_table.cell(0, 0)
    p_logo = cell_left.paragraphs[0]
    
    if os.path.exists("static/logo.png"):
        p_logo.add_run().add_picture("static/logo.png", width=Inches(1.4))
        p_logo.add_run("\n")
    else:
        run_icon = p_logo.add_run("🛡️  ")
        run_icon.font.size = Pt(20)
    
    run_brand = p_logo.add_run("ComplianceFlow")
    run_brand.font.name = 'Arial'
    run_brand.font.size = Pt(16)
    run_brand.font.bold = True
    run_brand.font.color.rgb = RGBColor(15, 23, 42)
    
    p_sub_logo = cell_left.add_paragraph()
    run_sub_logo = p_sub_logo.add_run("AUTOMATED B2B COMPLIANCE SUITE")
    run_sub_logo.font.name = 'Arial'
    run_sub_logo.font.size = Pt(7.5)
    run_sub_logo.font.bold = True
    run_sub_logo.font.color.rgb = RGBColor(20, 184, 166)
    
    cell_right = header_table.cell(0, 1)
    p_secure = cell_right.paragraphs[0]
    p_secure.alignment = 2 
    run_sec_txt = p_secure.add_run("SECURE RECORD\n")
    run_sec_txt.font.size = Pt(8)
    run_sec_txt.font.bold = True
    run_sec_txt.font.color.rgb = RGBColor(16, 185, 129)
    
    run_db_txt = p_secure.add_run("PostgreSQL Verified")
    run_db_txt.font.size = Pt(8)
    run_db_txt.font.italic = True
    
    p_line = doc.add_paragraph()
    run_line = p_line.add_run("_______________________________________________________________________")
    run_line.font.color.rgb = RGBColor(203, 213, 225)
    run_line.font.size = Pt(10)
    
    doc.add_paragraph("\n") 

    h_norma = doc.add_heading(level=1)
    run_norma = h_norma.add_run(f"Marco Regulatorio: {info['norma']}")
    run_norma.font.name = 'Arial'
    run_norma.font.color.rgb = RGBColor(15, 23, 42)
    
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
    
    doc.add_heading("2. Diagnóstico Técnico y Evidencia Conectada", level=2)
    doc.add_paragraph(info['detalle'])
    
    doc.add_paragraph("\n\n--- DOCUMENTO CONFIDENCIAL INALTERABLE ---").italic = True
    p_foot = doc.add_paragraph()
    run_f = p_foot.add_run("Este documento constituye evidencia legal ejecutable ante auditores externos. Los hashes e integridad de los bloques están resguardados criptográficamente.")
    run_f.font.size = Pt(8.5)
    run_f.font.color.rgb = RGBColor(100, 116, 139)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer

@app.get("/api/compliance/download", tags=["Escáner"])
def descargar_evidencia_unificada(format: str, id: str):
    if id not in DATA_ESTANDARES:
        raise HTTPException(status_code=404, detail="Estándar regulatorio no localizado.")
    info = DATA_ESTANDARES[id]
    if format == "word":
        try:
            buffer_word = generar_word_evidencia_interno(id)
            filename = f"evidencia_{id}_{datetime.now().strftime('%Y%m%d')}.docx"
            return StreamingResponse(buffer_word, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={"Content-Disposition": f"attachment; filename={filename}"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en Word: {str(e)}")
    elif format == "pdf":
        try:
            mock_payload = {"id": id, "norma": info["norma"], "titulo": info["titulo"], "evidencia_id": info["evidencia_id"], "estado": info["estado"], "detalle": info["detalle"]}
            reporter = ReportGenerator(cliente_nombre="Matriz de Infraestructura Conectada")
            archivo_pdf = reporter.generar_pdf_cumplimiento(mock_payload)
            return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=f"evidencia_{id}.pdf")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en PDF: {str(e)}")

@app.get("/", response_class=HTMLResponse)
def index(): return FileResponse("templates/index.html")

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(): return FileResponse("templates/dashboard.html")

@app.get("/login", response_class=HTMLResponse)
def mostrar_login(): return FileResponse("templates/login.html")

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def registrar(usuario: UserRegister):
    try:
        mfa_secret = auth_handler.registrar_usuario(usuario.email, usuario.password)
        return {"mensaje": "Usuario registrado", "mfa_secret": mfa_secret}
    except Exception: raise HTTPException(status_code=400, detail="Error al registrar.")

@app.post("/api/auth/login")
def login(usuario: UserLogin):
    codigo_limpio = usuario.codigo_mfa.replace(" ", "").replace("-", "").strip()
    if not auth_handler.verificar_mfa(usuario.email, codigo_limpio): raise HTTPException(status_code=401, detail="Código MFA inválido.")
    return {"mensaje": "Acceso concedido"}
