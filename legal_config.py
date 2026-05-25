class LegalShield:
    @staticmethod
    def obtener_clausula_responsabilidad():
        """Limitación de Responsabilidad para el Desarrollador Independiente"""
        return (
            "LIMITACIÓN DE RESPONSABILIDAD: Esta aplicación de Automated Compliance es una herramienta "
            "de asistencia técnica. El usuario reconoce que el software no garantiza la aprobación "
            "de auditorías (SOC 2/ISO 27001). La decisión final de cumplimiento recae exclusivamente "
            "en el cliente o su auditor certificado. El desarrollador no se hace responsable de "
            "interpretaciones legales erróneas." [cite: 20]
        )

    @staticmethod
    def obtener_politica_privacidad():
        """Transparencia en el manejo de datos"""
        return (
            "TRANSPARENCIA DE DATOS: Los datos recolectados vía API se utilizan únicamente para "
            "la generación de evidencia de cumplimiento. No vendemos ni compartimos datos con terceros. "
            "Toda la información se almacena con cifrado AES-256." [cite: 21]
        )
