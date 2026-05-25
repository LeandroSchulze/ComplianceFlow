import logging
from cryptography.fernet import Fernet
import os
from datetime import datetime

# Configuración de Logs de Auditoría (Requerimiento 2.3) 
logging.basicConfig(
    filename='auditoria_cumplimiento.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def registrar_evento(accion, usuario="Sistema"):
    """Registra quién hizo qué y cuándo """
    logging.info(f"Usuario: {usuario} | Acción: {accion}")

class SecurityManager:
    def __init__(self, key=None):
        # Implementa cifrado AES-256 [cite: 14]
        self.key = key or os.getenv("SECRET_KEY_AES").encode()
        self.fernet = Fernet(self.key)

    def cifrar_datos_sensibles(self, texto: str):
        """Cifra datos en reposo usando AES-256 [cite: 14]"""
        return self.fernet.encrypt(texto.encode())

    def descifrar_datos_sensibles(self, tokens: bytes):
        return self.fernet.decrypt(tokens).decode()
