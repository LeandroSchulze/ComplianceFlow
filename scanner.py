import boto3
from security import registrar_evento
from datetime import datetime

class ComplianceScanner:
    def __init__(self):
        self.s3 = boto3.client('s3')

    def escanear_infraestructura(self):
        """
        Detecta brechas de seguridad automáticamente para SOC 2 / ISO 27001 [cite: 6, 8]
        """
        registrar_evento("Iniciando escaneo de cumplimiento")
        reporte = {
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "brechas": []
        }

        try:
            buckets = self.s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                try:
                    # Verifica si el cifrado está activo (Control de SOC 2) 
                    self.s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    reporte["brechas"].append({
                        "recurso": f"S3 Bucket: {name}",
                        "error": "Cifrado ausente",
                        "prioridad": "Alta"
                    })
            
            registrar_evento(f"Escaneo finalizado. Brechas encontradas: {len(reporte['brechas'])}")
            return reporte
        except Exception as e:
            registrar_evento(f"Error en el escaneo: {str(e)}")
            return {"error": "No se pudo conectar a la API de la nube"}
