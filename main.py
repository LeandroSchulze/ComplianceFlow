# main.py
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
import os
from dotenv import load_dotenv

# Importamos tus módulos existentes
from scanner import ComplianceScanner
from reporter import ReportGenerator
from auth import AuthManager
from legal_config import LegalShield
from security import registrar_evento
from fastapi.responses import HTMLResponse

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

# --- ENDPOINTS FRONTEND (Sirven las vistas de la App) ---
@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
def index():
    """Sirve la Landing Page (El Gancho comercial)"""
    return FileResponse("templates/index.html")

@app.get("/dashboard", response_class=HTMLResponse, tags=["Frontend"])
def dashboard():
    """Sirve el Panel de Control Técnico"""
    return FileResponse("templates/dashboard.html")

@app.get("/login", response_class=HTMLResponse)
async def mostrar_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
    
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
        return {
            "mensaje": "Usuario registrado",
            "mfa_secret": mfa_secret
        }
    except Exception as e:
        registrar_evento(f"Error en registro: {str(e)}")
        raise HTTPException(status_code=400, detail="Error al registrar o usuario duplicado.")

@app.post("/api/auth/login", tags=["Autenticación"])
def login(usuario: UserLogin):
    es_valido = auth_handler.verificar_mfa(usuario.email, usuario.codigo_mfa)
    if not es_valido:
        raise HTTPException(status_code=401, detail="Código MFA inválido o expirado.")
    return {"mensaje": "Acceso concedido"}

# --- ENDPOINT DEL ESCÁNER (Generador de PDF) ---
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
