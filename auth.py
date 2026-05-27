# auth.py
import pyotp
import psycopg2
import os
from dotenv import load_dotenv
from security import SecurityManager, registrar_evento

load_dotenv()

class AuthManager:
    def __init__(self):
        # Tomamos la URL de conexión que Railway expone de forma automática
        self.database_url = os.getenv("DATABASE_URL")
        
        # Corrección técnica segura: SQLAlchemy/Psycopg2 a veces exigen 'postgresql://' en vez de 'postgres://'
        if self.database_url and self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace("postgres://", "postgresql://", 1)
            
        self._crear_tabla_usuarios()
        self.security = SecurityManager()

    def _get_connection(self):
        """Genera una conexión limpia a la base de datos PostgreSQL"""
        return psycopg2.connect(self.database_url)

    def _crear_tabla_usuarios(self):
        """Crea la tabla en Postgres si por alguna razón no existiera"""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios 
                                    (email VARCHAR(255) PRIMARY KEY, password_hash TEXT, mfa_secret TEXT)''')
                    conn.commit()
        except Exception as e:
            registrar_evento(f"Error al verificar/crear tabla usuarios en Postgres: {str(e)}")

    def registrar_usuario(self, email, password):
        mfa_secret = pyotp.random_base32()
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                # En Postgres usamos marcadores %s en lugar de ?
                cursor.execute("INSERT INTO usuarios (email, password_hash, mfa_secret) VALUES (%s, %s, %s)", 
                               (email, password, mfa_secret))
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
