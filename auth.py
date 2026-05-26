# auth.py
import pyotp
import sqlite3
import os
from dotenv import load_dotenv
from security import SecurityManager, registrar_evento

load_dotenv()

class AuthManager:
    def __init__(self):
        self.db = "usuarios_compliance.db"
        self._crear_tabla_usuarios()
        self.security = SecurityManager()

    def _crear_tabla_usuarios(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS usuarios 
                            (email TEXT PRIMARY KEY, password_hash TEXT, mfa_secret TEXT)''')

    def registrar_usuario(self, email, password):
        mfa_secret = pyotp.random_base32()
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO usuarios VALUES (?, ?, ?)", 
                         (email, password, mfa_secret))
        registrar_evento(f"Nuevo usuario registrado: {email}")
        return mfa_secret

    def verificar_mfa(self, email, codigo_ingresado):
        with sqlite3.connect(self.db) as conn:
            cursor = conn.execute("SELECT mfa_secret FROM usuarios WHERE email = ?", (email,))
            resultado = cursor.fetchone()
            
        if resultado:
            totp = pyotp.TOTP(resultado[0])
            # valid_window=1 le da 30 segundos de tolerancia antes y después al reloj del servidor
            if totp.verify(codigo_ingresado, valid_window=1):
                registrar_evento(f"MFA verificado para: {email}")
                return True
        return False
