# auth.py
import pyotp
import psycopg2
import os
import hashlib
from dotenv import load_dotenv
from security import SecurityManager, registrar_evento

load_dotenv()

class AuthManager:
    def __init__(self):
        self.database_url = os.getenv("DATABASE_URL")
        
        if self.database_url and self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace("postgres://", "postgresql://", 1)
            
        self._crear_tabla_usuarios()
        self.security = SecurityManager()

    def _get_connection(self):
        """Genera una conexión limpia a la base de datos PostgreSQL"""
        return psycopg2.connect(self.database_url)

    def _crear_tabla_usuarios(self):
        """Crea la tabla en Postgres con la columna de licencias Enterprise"""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios 
                                    (email VARCHAR(255) PRIMARY KEY, 
                                     password_hash TEXT, 
                                     mfa_secret TEXT,
                                     licencia_activa BOOLEAN DEFAULT FALSE)''')
                    conn.commit()
        except Exception as e:
            registrar_evento(f"Error al verificar/crear tabla usuarios en Postgres: {str(e)}")

    def registrar_usuario(self, email, password):
        mfa_secret = pyotp.random_base32()
        # 🔒 Hasheo seguro de la contraseña para evitar guardarla en texto plano
        password_protegida = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO usuarios (email, password_hash, mfa_secret) VALUES (%s, %s, %s)", 
                               (email, password_protegida, mfa_secret))
                conn.commit()
        registrar_evento(f"Nuevo usuario registrado en PostgreSQL: {email}")
        return mfa_secret

    def verificar_mfa(self, email, codigo_ingresado):
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT mfa_secret FROM usuarios WHERE email = %s", (email,))
                    resultado = cursor.fetchone()
            
            if resultado:
                totp = pyotp.TOTP(resultado[0])
                if totp.verify(codigo_ingresado, valid_window=1):
                    registrar_evento(f"MFA verificado de forma persistente para: {email}")
                    return True
        except Exception as e:
            registrar_evento(f"Error al verificar MFA en PostgreSQL: {str(e)}")
        return False

    def verificar_premium(self, email):
        """Consulta en la base de datos el estado de la licencia del cliente"""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT licencia_activa FROM usuarios WHERE email = %s", (email,))
                    resultado = cursor.fetchone()
                    if resultado:
                        return resultado[0]
        except Exception as e:
            registrar_evento(f"Error al verificar licencia en la base de datos: {str(e)}")
        return False

    def activar_premium(self, email):
        """Activa de forma inalterable el acceso Enterprise tras recibir el pago"""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE usuarios SET licencia_activa = TRUE WHERE email = %s", (email,))
                    conn.commit()
            registrar_evento(f"Licencia Enterprise ACTIVADA en base de datos para: {email}")
            return True
        except Exception as e:
            registrar_evento(f"Error al guardar la activación en base de datos: {str(e)}")
            return False
