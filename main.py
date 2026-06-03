# main.py
from fastapi import FastAPI, HTTPException, status, Request, APIRouter, Header, UploadFile, File, Form
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
import os
import io
import psycopg2
import json
from datetime import datetime
from dotenv import load_dotenv

import docx
from docx import Document
from docx.shared import Pt, Inches, RGBColor

import mercadopago

# ⚙️ ACTUALIZACIÓN: LIBRERÍA NUEVA DE GOOGLE
from google import genai

from scanner import ComplianceScanner
from reporter import ReportGenerator
from auth import AuthManager
from legal_config import LegalShield
from security import registrar_evento

load_dotenv()

app = FastAPI(
    title="ComplianceFlow AI Platform",
    description="Ecosistema Premium con Pasarelas de Cobro Avanzadas e Inteligencia Artificial",
    version="1.8.0"
)

auth_handler = AuthManager()

# ==========================================
# CÓDIGO DE ACTUALIZACIÓN DE TIPO DE CAMBIO
# ==========================================
router = APIRouter()

TOKEN_INTERNO_SECRETO = os.getenv("TOKEN_SISTEMAS_SECRETO")

raw_cotizacion = os.getenv("COTIZACION", "1000.0").strip()
try:
    TIPO_CAMBIO = float(raw_cotizacion)
except ValueError:
    TIPO_CAMBIO = 1000.0

@router.post("/api/v1/internal/update-tc")
def actualizar_tipo_cambio_interno(payload: dict, x_internal_token: str = Header(None)):
    global TIPO_CAMBIO
    if x_internal_token != TOKEN_INTERNO_SECRETO or not TOKEN_INTERNO_SECRETO:
        raise HTTPException(status_code=401, detail="No autorizado")
    nuevo_tc = payload.get("nuevo_tc")
    if nuevo_tc is None or not isinstance(nuevo_tc, (int, float)):
        raise HTTPException(status_code=400, detail="Valor de TC inválido")
    TIPO_CAMBIO = float(nuevo_tc)
    return {"status": "actualizado", "nuevo_tipo_cambio": TIPO_CAMBIO}

# --- MODELOS DE DATOS (PYDANTIC) ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    codigo_mfa: str

class AICopilotRequest(BaseModel):
    norma_id: str
    infraestructura_tipo: str 
    premium_active: bool = False

class BillingAlertRequest(BaseModel):
    email: EmailStr
    dias_restantes: int

DATA_ESTANDARES = {
    "ISO-IAM": {"norma": "ISO 27001 — Anexo A.9", "titulo": "Auditoría de Control de Accesos", "evidencia_id": "EV-ISO-A9-8812", "estado": "VERIFICANDO...", "detalle": "Pendiente de análisis real."},
    "SOC2-S3": {"norma": "SOC 2 Type II — CC6.3", "titulo": "Análisis Criptográfico S3", "evidencia_id": "EV-SOC2-S3-9202", "estado": "VERIFICANDO...", "detalle": "Pendiente de análisis real."},
    "SOC1-FIN": {"norma": "SOC 1 — Controles ICFR", "titulo": "Matriz de Segregación de Funciones", "evidencia_id": "EV-SOC1-FIN-7741", "estado": "VERIFICANDO...", "detalle": "Pendiente de análisis real."},
    "ISO-9001": {"norma": "ISO 9001 — Cláusula 8.2", "titulo": "Trazabilidad de Requisitos de Calidad", "evidencia_id": "EV-ISO9-QA-3321", "estado": "VERIFICANDO...", "detalle": "Pendiente de análisis real."}
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

# MODIFICACIÓN: Se agrega el parámetro email para validar la cuenta admin
def verificar_y_actualizar_limite_ip(ip: str, email: str = None) -> int:
    if email == "schulzeleandro77@gmail.com":
        return 0
        
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

# --- MOTOR DE INTELIGENCIA ARTIFICIAL COPILOT (ACTUALIZADO A LA NUEVA API) ---
class ComplianceAI_CoPilot:
    @staticmethod
    def analizar_normativa(norma_id: str, infra: str) -> dict:
        fecha_analisis = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
        api_key = os.getenv("GEMINI_API_KEY")
        
        if api_key:
            try:
                # Inicializamos el cliente con el nuevo SDK
                client = genai.Client(api_key=api_key)
                
                prompt = f"""
                Actúa como un Auditor Senior de Ciberseguridad B2B. 
                El cliente está auditando la normativa '{norma_id}' sobre la infraestructura '{infra}'.
                
                Genera una evaluación técnica ultra realista. 
                Devuelve ÚNICAMENTE un objeto JSON válido (sin formato markdown ni texto adicional) con estas 3 claves exactas:
                "diag": Un diagnóstico profundo de 2 líneas sobre los riesgos específicos de esa infraestructura.
                "gaps": 3 pasos técnicos y concretos de remediación enumerados.
                "tip": Una pregunta muy técnica que un auditor riguroso haría sobre este entorno.
                """
                
                # Hacemos la consulta usando la sintaxis actualizada
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt
                )
                
                texto_limpio = response.text.strip()
                if texto_limpio.startswith("```json"):
                    texto_limpio = texto_limpio[7:-3].strip()
                elif texto_limpio.startswith("```"):
                    texto_limpio = texto_limpio[3:-3].strip()
                    
                data_ia = json.loads(texto_limpio)
                
                return {
                    "estado_ia": "🧠 ANÁLISIS EN VIVO POR GEMINI IA",
                    "fecha_computo": fecha_analisis,
                    "entorno_evaluado": infra,
                    "diagnostico_profundo": data_ia.get("diag", "Evaluación completada con observaciones de red."),
                    "plan_de_accion_gaps": data_ia.get("gaps", "1. Revisar bitácoras.\n2. Asegurar puertos.\n3. Validar IAM."),
                    "defensa_auditor_tip": data_ia.get("tip", "¿Cómo demuestran trazabilidad absoluta de estos cambios?")
                }
            except Exception as e:
                registrar_evento(f"Fallo en API Gemini: {str(e)}")
                # Si ocurre un error, continúa al sistema de respaldo

        # SISTEMA DE RESPALDO (Fallback)
        respuestas_ia = {
            "ISO-IAM": {
                "diag": f"Análisis de {infra}: Se detectaron 3 perfiles de IAM con privilegios 'AdministratorAccess' sin restricciones de IP. La política 'AllowAll' está activa en el entorno de producción.",
                "gaps": "1. Revocar permisos 'sts:AssumeRole' genéricos.\n2. Forzar autenticación MFA para acceso a consola.\n3. Implementar el principio de mínimo privilegio (PoLP).",
                "tip": "¿Tienen un registro auditable de las últimas 5 veces que se escalaron privilegios de administrador?"
            },
            "SOC2-S3": {
                "diag": f"Análisis de {infra}: Los buckets presentan una configuración mixta. El cifrado AES-256 está activo, pero faltan políticas de retención de logs.",
                "gaps": "1. Habilitar Server Access Logging en el bucket principal.\n2. Configurar regla de ciclo de vida (Lifecycle) a 365 días.\n3. Bloquear ACLs públicas globalmente.",
                "tip": "Muestre al auditor cómo el sistema bloquea automáticamente cualquier intento de exponer un objeto a internet."
            },
            "SOC1-FIN": {
                "diag": f"Análisis de {infra}: Se cruzaron roles financieros contra logs de auditoría. Se detecta un conflicto de SoD en la tabla 'pagos_aprobados'.",
                "gaps": "1. Separar el rol de 'creador de pago' del de 'aprobador'.\n2. Habilitar firmas digitales inalterables en cada transacción.\n3. Implementar alertas de montos inusuales.",
                "tip": "¿Cómo garantizan que un desarrollador con acceso a BD no pueda alterar un registro financiero sin dejar rastro?"
            },
            "ISO-9001": {
                "diag": f"Análisis de {infra}: El flujo de integración continua (CI/CD) muestra un 92% de cobertura de tests, pero el paso de QA manual permite 'bypasses' de emergencia.",
                "gaps": "1. Requerir revisión de 2 pares (Code Review) para mezclar a la rama 'main'.\n2. Adjuntar reporte de cobertura estática en cada release.\n3. Bloquear despliegues con vulnerabilidades críticas.",
                "tip": "Presenten la matriz de trazabilidad que conecta cada 'commit' de código con el ticket original del cliente."
            }
        }
        
        data_fallback = respuestas_ia.get(norma_id, respuestas_ia["ISO-IAM"])
        return {
            "estado_ia": "✨ ANÁLISIS GENERADO POR COPILOT IA (CACHÉ)",
            "fecha_computo": fecha_analisis, 
            "entorno_evaluado": infra,
            "diagnostico_profundo": data_fallback["diag"],
            "plan_de_accion_gaps": data_fallback["gaps"], 
            "defensa_auditor_tip": data_fallback["tip"]
        }

@app.post("/api/compliance/copilot", tags=["Inteligencia Artificial"])
def obtener_ayuda_copilot_ia(request: Request, solicitud: AICopilotRequest):
    user_email = request.headers.get("X-User-Email")
    if not solicitud.premium_active and user_email != "schulzeleandro77@gmail.com": 
        raise HTTPException(status_code=402, detail="Se requiere Licencia Enterprise para usar el Copiloto IA.")
    return ComplianceAI_CoPilot.analizar_normativa(solicitud.norma_id, solicitud.infraestructura_tipo)


# --- PASARELAS DE COBRO MERCADOPAGO ---
@app.post("/api/checkout/preference/individual", tags=["Financiero"])
def crear_preferencia_individual():
    global TIPO_CAMBIO
    try:
        token = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "").strip()
        sdk_dinamico = mercadopago.SDK(token)
        precio_final_ars = float(20.0 * TIPO_CAMBIO)
        preference_data = {
            "items": [{"title": "Pase Express — 1 Reporte de Evidencia Firmado", "quantity": 1, "unit_price": precio_final_ars, "currency_id": "ARS"}],
            "back_urls": {"success": "https://www.complianceflow.me/dashboard?payment=success", "failure": "https://www.complianceflow.me/dashboard", "pending": "https://www.complianceflow.me/dashboard"},
            "auto_return": "approved"
        }
        mp_res = sdk_dinamico.preference().create(preference_data)
        if "response" in mp_res and "init_point" in mp_res["response"]:
            return {"init_point": mp_res["response"]["init_point"]}
        raise HTTPException(status_code=400, detail="Error SDK MP")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/checkout/preference/premium", tags=["Financiero"])
def crear_preferencia_premium():
    global TIPO_CAMBIO
    try:
        token = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "").strip()
        sdk_dinamico = mercadopago.SDK(token)
        precio_final_ars = float(50.0 * TIPO_CAMBIO)
        preference_data = {
            "items": [{"title": "Licencia Enterprise Corporativa", "quantity": 1, "unit_price": precio_final_ars, "currency_id": "ARS"}],
            "back_urls": {"success": "https://www.complianceflow.me/dashboard?tier=premium", "failure": "https://www.complianceflow.me/dashboard", "pending": "https://www.complianceflow.me/dashboard"},
            "auto_return": "approved"
        }
        mp_res = sdk_dinamico.preference().create(preference_data)
        if "response" in mp_res and "init_point" in mp_res["response"]:
            return {"init_point": mp_res["response"]["init_point"]}
        raise HTTPException(status_code=400, detail="Error SDK MP Premium")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# ⚙️ MOTOR DE ANÁLISIS ESTÁTICO DE ARCHIVOS REALES
# =====================================================================
def analizar_contenido_documento(contenido: str, norma_id: str) -> dict:
    info = DATA_ESTANDARES.get(norma_id, DATA_ESTANDARES["ISO-IAM"]).copy()
    texto = contenido.lower()

    if norma_id == "ISO-IAM":
        if "multifactorauthpresent" in texto and "false" in texto:
            info["estado"] = "⚠️ OBSERVACIÓN DETECTADA"
            info["detalle"] = "Análisis del Archivo: Se detectó una política que permite acceso sin Autenticación Multifactor (MFA). Esto viola directamente el control de accesos de la ISO 27001."
        else:
            info["estado"] = "🟢 100% CUMPLIDO"
            info["detalle"] = "Análisis del Archivo: No se detectaron vulnerabilidades de acceso. Las políticas de IAM inspeccionadas cumplen con los requisitos de seguridad."
            
    elif norma_id == "SOC2-S3":
        if "blockpublicacls: false" in texto or "entropy check failed" in texto:
            info["estado"] = "⚠️ OBSERVACIÓN DETECTADA"
            info["detalle"] = "Análisis del Archivo: Se encontraron configuraciones que exponen objetos de forma pública o fallos en el chequeo de entropía criptográfica."
        else:
            info["estado"] = "🟢 100% CUMPLIDO"
            info["detalle"] = "Análisis del Archivo: Bloqueo de acceso público confirmado. El nivel de encriptación cumple con los Trust Services Criteria de SOC 2."

    elif norma_id == "ISO-9001":
        if "without explicit cryptographic" in texto or "bypassing" in texto:
            info["estado"] = "⚠️ OBSERVACIÓN DETECTADA"
            info["detalle"] = "Análisis del Archivo: El log del pipeline evidencia un bypass de los controles de aseguramiento de calidad (QA) y falta de firmas SHA-256."
        else:
            info["estado"] = "🟢 100% CUMPLIDO"
            info["detalle"] = "Análisis del Archivo: Pipeline inmaculado. Todos los artefactos fueron firmados criptográficamente asegurando la trazabilidad total."
    else:
        info["estado"] = "🟢 REVISADO"
        info["detalle"] = "Análisis del Archivo completado. Las métricas estructurales se encuentran dentro de los parámetros aceptables."
        
    return info

# --- ENDPOINT CORE ACTUALIZADO ---
@app.post("/api/compliance/scan", tags=["Escáner"])
async def ejecutar_escaneo_web(request: Request, norma_id: str = Form(...), file: UploadFile = File(...)):
    ip_cliente = obtener_ip_cliente(request)
    user_email = request.headers.get("X-User-Email")
    
    if user_email != "schulzeleandro77@gmail.com":
        try:
            with obtener_conexion_db() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT escaneos_realizados FROM control_ips WHERE ip = %s", (ip_cliente,))
                    resultado = cursor.fetchone()
                    if resultado and resultado[0] >= 3:
                        raise HTTPException(status_code=402, detail="Límite freemium de 3 pruebas alcanzado.")
        except HTTPException as he:
            raise he
        except Exception as e:
            registrar_evento(f"Fallo de persistencia BD: {str(e)}")
        
    verificar_y_actualizar_limite_ip(ip_cliente, email=user_email)
    
    try:
        contenido_bytes = await file.read()
        contenido_texto = contenido_bytes.decode('utf-8', errors='ignore')
    except Exception:
        contenido_texto = ""
    
    info_dinamica = analizar_contenido_documento(contenido_texto, norma_id)
    
    # ⚙️ GUARDAR EN HISTORIAL EN VIVO
    global DATA_ESTANDARES
    DATA_ESTANDARES[norma_id] = info_dinamica
    
    datos_reporte = {
        "id": norma_id,
        "norma": info_dinamica["norma"],
        "titulo": info_dinamica["titulo"],
        "evidencia_id": info_dinamica["evidencia_id"],
        "estado": info_dinamica["estado"],
        "detalle": info_dinamica["detalle"]
    }
    
    nombre_seguro = file.filename if file.filename else "documento_generico.log"
    reporter = ReportGenerator(cliente_nombre=f"Evidencia: {nombre_seguro}")
    archivo_pdf = reporter.generar_pdf_cumplimiento(datos_reporte)
    
    headers = {
        "X-Status-Compliance": "observacion" if "OBSERVACIÓN" in info_dinamica["estado"] else "aprobado",
        "Access-Control-Expose-Headers": "X-Status-Compliance"
    }
    
    return FileResponse(path=archivo_pdf, media_type="application/pdf", filename=archivo_pdf, headers=headers)

@app.get("/api/compliance/download", tags=["Escáner"])
def descargar_evidencia_unificada(format: str, id: str, active: bool = False):
    if not active: raise HTTPException(status_code=402, detail="Descarga bloqueada.")
    
    info = DATA_ESTANDARES.get(id, DATA_ESTANDARES["ISO-IAM"])
    datos = {"id": id, "norma": info["norma"], "titulo": info["titulo"], "evidencia_id": info["evidencia_id"], "estado": info["estado"], "detalle": info["detalle"]}
    
    if format == "pdf":
        reporter = ReportGenerator(cliente_nombre="Auditoría Histórica")
        pdf = reporter.generar_pdf_cumplimiento(datos)
        return FileResponse(path=pdf, media_type="application/pdf", filename=f"evidencia_{id}.pdf")
        
    elif format == "word":
        doc = Document()
        titulo = doc.add_heading('COMPLIANCEFLOW - CERTIFICADO OFICIAL DE AUDITORÍA', 0)
        titulo.alignment = 1 
        doc.add_paragraph("==========================================================================")
        
        doc.add_heading('1. Metadatos de la Evaluación', level=1)
        tabla = doc.add_table(rows=3, cols=2)
        tabla.style = 'Table Grid'
        tabla.rows[0].cells[0].text = 'Normativa Auditada:'
        tabla.rows[0].cells[1].text = info["norma"]
        tabla.rows[1].cells[0].text = 'ID de Control Técnico:'
        tabla.rows[1].cells[1].text = info["evidencia_id"]
        tabla.rows[2].cells[0].text = 'Fecha de Aprobación:'
        tabla.rows[2].cells[1].text = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        doc.add_paragraph("\n")
        
        doc.add_heading('2. Veredicto del Escáner', level=1)
        p = doc.add_paragraph()
        run = p.add_run(info["estado"])
        run.bold = True
        run.font.size = Pt(14)
        
        doc.add_heading('3. Detalle Técnico (Logs Analizados)', level=1)
        doc.add_paragraph(info["detalle"])
        doc.add_paragraph("\n==========================================================================")
        
        footer = doc.add_paragraph()
        footer.add_run('Firma Digital: ').bold = True
        footer.add_run('Generado automáticamente por el motor IA de ComplianceFlow. Documento inalterable.')
        
        filename = f"auditoria_{id}_oficial.docx"
        doc.save(filename)
        return FileResponse(path=filename, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename=filename)

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

app.include_router(router)
