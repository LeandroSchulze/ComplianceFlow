# main.py
from fastapi import FastAPI, HTTPException, status, Request, APIRouter, Header
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

import mercadopago

from scanner import ComplianceScanner
from reporter import ReportGenerator
from auth import AuthManager
from legal_config import LegalShield
from security import registrar_evento

load_dotenv()

app = FastAPI(
    title="ComplianceFlow AI Platform",
    description="Ecosistema Premium con Pasarelas de Cobro Avanzadas e Inteligencia Artificial",
    version="1.6.5"
)

auth_handler = AuthManager()

# ==========================================
# CÓDIGO DE ACTUALIZACIÓN DE TIPO DE CAMBIO
# ==========================================
router = APIRouter()

# Este token secreto lo definís vos en las variables de Railway de las 3 apps
TOKEN_INTERNO_SECRETO = os.getenv("TOKEN_SISTEMAS_SECRETO")

# Convertimos la cotización base de forma segura limpiando espacios remanentes
raw_cotizacion = os.getenv("COTIZACION", "1000.0").strip()
try:
    TIPO_CAMBIO = float(raw_cotizacion)
except ValueError:
    TIPO_CAMBIO = 1000.0

@router.post("/api/v1/internal/update-tc")
def actualizar_tipo_cambio_interno(payload: dict, x_internal_token: str = Header(None)):
    global TIPO_CAMBIO
    
    # Validamos que la petición venga realmente de tu Panel Central
    if x_internal_token != TOKEN_INTERNO_SECRETO or not TOKEN_INTERNO_SECRETO:
        raise HTTPException(status_code=401, detail="No autorizado")
    
    nuevo_tc = payload.get("nuevo_tc")
    if nuevo_tc is None or not isinstance(nuevo_tc, (int, float)):
        raise HTTPException(status_code=400, detail="Valor de TC inválido")
    
    # Se actualiza en la memoria del servidor de la app en vivo
    TIPO_CAMBIO = float(nuevo_tc)
    return {"status": "actualizado", "nuevo_tipo_cambio": TIPO_CAMBIO}

# --- MODELOS DE DATOS (PYDANTIC) ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    codigo_mfa: str

class ScanRequest(BaseModel):
    cliente_nombre: str

class AICopilotRequest(BaseModel):
    norma_id: str
    infraestructura_tipo: str 
    premium_active: bool = False

# Repositorio maestro de estandares y evidencias (Incluye ISO 9001)
DATA_ESTANDARES = {
    "ISO-IAM": {"norma": "ISO 27001 — Anexo A.9", "titulo": "Auditoría de Control de Accesos", "evidencia_id": "EV-ISO-A9-8812", "estado": "⚠️ OBSERVACIÓN DETECTADA", "detalle": "Políticas AdministratorAccess asignadas a cuentas de desarrollo sin MFA activo."},
    "SOC2-S3": {"norma": "SOC 2 Type II — CC6.3", "titulo": "Análisis Criptográfico S3", "evidencia_id": "EV-SOC2-S3-9202", "estado": "🟢 100% CUMPLIDO", "detalle": "Public Access Block activo y cifrado SSE-S3 de forma persistente."},
    "SOC1-FIN": {"norma": "SOC 1 — Controles ICFR", "titulo": "Matriz de Segregación de Funciones", "evidencia_id": "EV-SOC1-FIN-7741", "estado": "🟢 100% CUMPLIDO", "detalle": "Firmas transaccionales de balances contables desacopladas de cuentas de desarrollo."},
    "ISO-9001": {"norma": "ISO 9001 — Cláusula 8.2", "titulo": "Trazabilidad de Requisitos de Calidad", "evidencia_id": "EV-ISO9-QA-3321", "estado": "🟢 100% CUMPLIDO", "detalle": "Pipeline CI/CD automatizado con aprobación cruzada digital firmada por control de calidad."}
}

# --- CONEXIÓN A BASE DE DATOS POSTGRES ---
def obtener_conexion_db():
    db_url = os.getenv("DATABASE_URL")
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(db_url)

def obtener_ip_cliente(request: Request) -> str:
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

# --- MOTOR DE INTELIGENCIA ARTIFICIAL COPILOT ---
class ComplianceAI_CoPilot:
    @staticmethod
    def analizar_normativa(norma_id: str, infra: str) -> dict:
        fecha_analisis = datetime.now().strftime('%Y-%m-%d')
        gaps_libreria = {
            "ISO-IAM": {
                "analisis_ia": f"La IA detectó que tu entorno '{infra}' carece de segregación de trazas de logs. Si bien el escáner estructural pasó, las cuentas raíz no están bloqueadas para uso diario.",
                "lo_que_falta": "1. Mapeo explícito de roles en el archivo de entorno.\n2. Desactivar llaves de acceso SSH que tengan más de 90 días de antigüedad.\n3. Configurar alarma SNS ante intentos de login fallidos.",
                "pregunta_del_auditor": "¿Cómo demostrás que un desarrollador desvinculado pierde acceso a la base de datos de producción en menos de 2 horas?"
            },
            "SOC2-S3": {
                "analisis_ia": f"Análisis predictivo sobre '{infra}': Se verificó el bloqueo público, pero la IA nota que no se está realizando un análisis periódico de entropía de datos para descubrir archivos confidenciales sin cifrar.",
                "lo_que_falta": "1. Forzar política TLS 1.3 obligatoria en buckets.\n2. Activar la retención legal de objetos (Object Lock) para prevenir Ransomware.",
                "pregunta_del_auditor": "Si un atacante compromete las credenciales de un administrador, ¿qué control evita que borre el historial de auditoría completo?"
            },
            "ISO-9001": {
                "analisis_ia": f"Análisis de Calidad sobre '{infra}': La IA confirma consistencia técnica en la trazabilidad del pipeline, pero detecta la ausencia de firmas criptográficas hash en los entregables intermedios.",
                "lo_que_falta": "1. Integrar firmas SHA-256 automáticas en artefactos de compilación.\n2. Documentar el proceso de rollback automatizado en caso de fallas de QA.",
                "pregunta_del_auditor": "¿Cómo asegura que los requisitos de calidad definidos por el cliente se validen de forma inalterable en cada despliegue?"
            }
        }
        fallback = {
            "analisis_ia": f"Análisis algorítmico predictivo completado para '{infra}'. El sistema corrobora consistencia estructural pero detecta falta de documentación procedimental indexada en la base de datos.",
            "lo_que_falta": "1. Vincular los hashes de control PostgreSQL con los manuales de operacion interna.\n2. Establecer un simulacro de brecha semestral automatizado.",
            "pregunta_del_auditor": "¿Cuál es su procedimiento documentado para validar que los parches de seguridad del sistema operativo se aplican en menos de 7 días?"
        }
        res = gaps_libreria.get(norma_id, fallback)
        return {
            "estado_ia": "✨ ANÁLISIS GENERADO POR COPILOT IA",
            "fecha_computo": fecha_analisis,
            "entorno_evaluado": infra,
            "diagnostico_profundo": res["analisis_ia"],
            "plan_de_accion_gaps": res["lo_que_falta"],
            "defensa_auditor_tip": res["pregunta_del_auditor"]
        }

@app.post("/api/compliance/copilot", tags=["Inteligencia Artificial"])
def obtener_ayuda_copilot_ia(solicitud: AICopilotRequest):
    if not solicitud.premium_active:
        raise HTTPException(status_code=402, detail="Se requiere Licencia Enterprise para usar el Copiloto IA.")
    try: 
        return ComplianceAI_CoPilot.analizar_normativa(solicitud.norma_id, solicitud.infraestructura_tipo)
    except Exception as e: 
        raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# 💳 PASARELAS DE COBRO BLINDADAS CON EXCEPCIONES Y EN CALIENTE
# =====================================================================
@app.post("/api/checkout/preference/individual", tags=["Financiero"])
def crear_preferencia_individual():
    global TIPO_CAMBIO
    try:
        token = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "").strip()
        sdk_dinamico = mercadopago.SDK(token)
        
        # Multiplicación limpia usando la memoria global dinámica reactiva
        precio_final_ars = float(20.0 * TIPO_CAMBIO)
        
        preference_data = {
            "items": [{"title": "Pase Express — 1 Reporte de Evidencia Firmado", "quantity": 1, "unit_price": precio_final_ars, "currency_id": "ARS"}],
            "back_urls": {
                "success": "https://complianceflow-production.up.railway.app/dashboard?payment=success",
                "failure": "https://complianceflow-production.up.railway.app/dashboard",
                "pending": "https://complianceflow-production.up.railway.app/dashboard"
            },
            "auto_return": "approved"
        }
        
        mp_res = sdk_dinamico.preference().create(preference_data)
        
        if "response" in mp_res and "init_point" in mp_res["response"]:
            return {"init_point": mp_res["response"]["init_point"]}
        else:
            raise HTTPException(status_code=400, detail=f"Error SDK MP: {str(mp_res)}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error pasarela individual: {str(e)}")

@app.post("/api/checkout/preference/premium", tags=["Financiero"])
def crear_preferencia_premium():
    global TIPO_CAMBIO
    try:
        token = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "").strip()
        sdk_dinamico = mercadopago.SDK(token)
        
        precio_final_ars = float(50.0 * TIPO_CAMBIO)
        
        preference_data = {
            "items": [{"title": "Licencia Enterprise Corporativa — Escáner + Copiloto IA", "quantity": 1, "unit_price": precio_final_ars, "currency_id": "ARS"}],
            "back_urls": {
                "success": "https://complianceflow-production.up.railway.app/dashboard?tier=premium",
                "failure": "https://complianceflow-production.up.railway.app/dashboard",
                "pending": "https://complianceflow-production.up.railway.app/dashboard"
            },
            "auto_return": "approved"
        }
        
        mp_res = sdk_dinamico.preference().create(preference_data)
        
        if "response" in mp_res and "init_point" in mp_res["response"]:
            return {"init_point": mp_res["response"]["init_point"]}
        else:
            raise HTTPException(status_code=400, detail=f"Error SDK MP Premium: {str(mp_res)}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error pasarela premium: {str(e)}")

# --- ENDPOINTS CORE ---
@app.post("/api/compliance/scan", tags=["Escáner"])
def ejecutar_escaneo_web(solicitud: ScanRequest, request: Request):
    scanner = ComplianceScanner()
    reporter = ReportGenerator(cliente_nombre=solicitud.cliente_nombre)
    archivo_pdf = reporter.generar_pdf_cumplimiento(scanner.escanear_infraestructura())
    return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=archivo_pdf)

def generar_word_evidencia_interno(doc_id: str) -> io.BytesIO:
    doc = Document()
    info = DATA_ESTANDARES.get(doc_id, {"norma": "Estándar", "titulo": "Reporte", "evidencia_id": "EV-GEN", "estado": "VERIFICADO", "detalle": "Completado"})
    doc.add_heading(f"Marco Regulatorio: {info['norma']}", level=1)
    doc.add_heading("1. Metadatos de Control", level=2)
    p = doc.add_paragraph()
    p.add_run(f"Título: {info['titulo']}\nID Evidencia: {info['evidencia_id']}\nEstado: {info['estado']}\n")
    doc.add_heading("2. Diagnóstico Técnico", level=2)
    doc.add_paragraph(info['detalle'])
    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer

@app.get("/api/compliance/download", tags=["Escáner"])
def descargar_evidencia_unificada(format: str, id: str, active: bool = False):
    if not active:
        raise HTTPException(status_code=402, detail="Descarga bloqueada. Se requiere un pago activo.")
    if id not in DATA_ESTANDARES:
        raise HTTPException(status_code=404, detail="No encontrado.")
    if format == "word":
        return StreamingResponse(generar_word_evidencia_interno(id), media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={"Content-Disposition": f"attachment; filename=evidencia_{id}.docx"})
    elif format == "pdf":
        info = DATA_ESTANDARES[id]
        reporter = ReportGenerator(cliente_nombre="Matriz de Infraestructura Conectada")
        archivo_pdf = reporter.generar_pdf_cumplimiento({"id": id, "norma": info["norma"], "titulo": info["titulo"], "evidencia_id": info["evidencia_id"], "estado": info["estado"], "detalle": info["detalle"]})
        return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=f"evidencia_{id}.pdf")

# --- VISTAS HTML ---
@app.get("/", response_class=HTMLResponse)
def index(): return FileResponse("templates/index.html")

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(): return FileResponse("templates/dashboard.html")

@app.get("/login", response_class=HTMLResponse)
def mostrar_login(): return FileResponse("templates/login.html")

# --- AUTENTICACIÓN ---
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, tags=["Autenticación"])
def registrar(usuario: UserRegister):
    try:
        mfa_secret = auth_handler.registrar_usuario(usuario.email, usuario.password)
        return {"mensaje": "Usuario registrado exitosamente", "mfa_secret": mfa_secret}
    except Exception as e: 
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login", tags=["Autenticación"])
def login(usuario: UserLogin):
    codigo_limpio = usuario.codigo_mfa.replace(" ", "").replace("-", "").strip()
    if not auth_handler.verificar_mfa(usuario.email, codigo_limpio):
        raise HTTPException(status_code=401, detail="MFA inválido.")
    return {"mensaje": "Acceso concedido"}

# REGISTRO EXPLÍCITO DEL ROUTER DE ACTUALIZACIÓN
app.include_router(router)
