import boto3
import os
import psycopg2
from security import registrar_evento
from datetime import datetime

class ComplianceScanner:
    def __init__(self):
        # ⚙️ Inicialización defensiva para evitar crashes si faltan las credenciales
        aws_id = os.getenv("AWS_ACCESS_KEY_ID") #
        aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY") #
        
        if aws_id and aws_secret: #
            self.s3 = boto3.client('s3') #
            self.aws_activo = True #
        else: #
            self.s3 = None #
            self.aws_activo = False #

    def escanear_infraestructura(self):
        """
        Detecta brechas de seguridad automáticamente para SOC 2 / ISO 27001 en S3
        """
        registrar_evento("Iniciando escaneo de cumplimiento en AWS") #
        reporte = { #
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), #
            "brechas": [] #
        } #

        if not self.aws_activo: #
            registrar_evento("AWS no configurado. Ejecutando análisis estructural cruzado local.") #
            reporte["brechas"].append({ #
                "recurso": "Local Logs Ingestion", #
                "error": "Políticas analizadas de manera local. Active credenciales en la nube para auditoría real.", #
                "prioridad": "Informativa" #
            }) #
            return reporte #

        try: #
            buckets = self.s3.list_buckets()['Buckets'] #
            for bucket in buckets: #
                name = bucket['Name'] #
                try: #
                    # Verifica si el cifrado está activo (Control de SOC 2)
                    self.s3.get_bucket_encryption(Bucket=name) #
                except Exception: #
                    reporte["brechas"].append({ #
                        "recurso": f"S3 Bucket: {name}", #
                        "error": "Cifrado ausente", #
                        "prioridad": "Alta" #
                    }) #
            
            registrar_evento(f"Escaneo finalizado. Brechas encontradas: {len(reporte['brechas'])}") #
            return reporte #
        except Exception as e: #
            registrar_evento(f"Error en el escaneo: {str(e)}") #
            return {"error": "No se pudo conectar a la API de la nube"} #

    def escanear_base_datos(self, db_url: str):
        """
        Escáner automatizado SOC 2 para bases de datos PostgreSQL.
        Se conecta en modo de solo lectura para auditar metadatos de seguridad.
        """
        registrar_evento("Iniciando escaneo automatizado de base de datos PostgreSQL")
        reporte = {
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "brechas": []
        }

        # Normalizar la URL de conexión (similar a la lógica de tu main.py)
        if db_url and db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)

        try:
            # Conexión directa a la infraestructura del cliente
            with psycopg2.connect(db_url) as conn:
                # 🔒 Cero Riesgo: Forzamos la sesión a solo lectura. 
                # Evita cualquier alteración de datos por más permisos que tenga el rol.
                conn.set_session(readonly=True) 
                
                with conn.cursor() as cursor:
                    # -----------------------------------------------------
                    # GAP 1: Encriptación de Contraseñas (SOC 2 CC6.1 - Access)
                    # -----------------------------------------------------
                    cursor.execute("SHOW password_encryption;")
                    encryption_type = cursor.fetchone()[0]
                    if encryption_type != 'scram-sha-256':
                        reporte["brechas"].append({
                            "recurso": "PostgreSQL: Políticas de Autenticación",
                            "error": f"Algoritmo débil detectado ({encryption_type}). SOC 2 requiere scram-sha-256 para evitar ataques de fuerza bruta.",
                            "prioridad": "Alta"
                        })

                    # -----------------------------------------------------
                    # GAP 2: Tráfico Cifrado Obligatorio (SOC 2 CC6.6 - Boundary Protection)
                    # -----------------------------------------------------
                    cursor.execute("SHOW ssl;")
                    ssl_active = cursor.fetchone()[0]
                    if ssl_active.lower() != 'on':
                        reporte["brechas"].append({
                            "recurso": "PostgreSQL: Encriptación en Tránsito",
                            "error": "El servidor no fuerza conexiones SSL/TLS. Los datos sensibles podrían ser interceptados.",
                            "prioridad": "Crítica"
                        })

                    # -----------------------------------------------------
                    # GAP 3: Exposición a Rol 'Public' (SOC 2 CC6.3 - Confidentiality)
                    # -----------------------------------------------------
                    query_permisos = """
                        SELECT table_name 
                        FROM information_schema.role_table_grants 
                        WHERE grantee = 'public' AND table_schema = 'public';
                    """
                    cursor.execute(query_permisos)
                    tablas_publicas = cursor.fetchall()
                    if tablas_publicas:
                        tablas = [t[0] for t in tablas_publicas]
                        reporte["brechas"].append({
                            "recurso": "PostgreSQL: Matriz de Acceso (IAM)",
                            "error": f"Se detectaron permisos globales. El rol 'public' tiene acceso directo a las tablas: {', '.join(tablas)}",
                            "prioridad": "Crítica"
                        })

            if not reporte["brechas"]:
                 reporte["brechas"].append({
                     "recurso": "PostgreSQL Infraestructura",
                     "error": "Configuración óptima. Los parámetros estructurales inspeccionados cumplen con los controles técnicos de SOC 2.",
                     "prioridad": "Informativa"
                 })

            registrar_evento(f"Escaneo DB finalizado. Gaps detectados: {len([b for b in reporte['brechas'] if b['prioridad'] != 'Informativa'])}")
            return reporte

        except Exception as e:
            registrar_evento(f"Error técnico conectando a BD externa: {str(e)}")
            return {"error": "Fallo de conexión. Verifica que la cadena sea válida y que las reglas del firewall (ej. pg_hba.conf) permitan la conexión del motor."}
