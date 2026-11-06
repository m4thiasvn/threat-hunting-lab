# Arquitectura del Threat Hunting Lab

## Descripción

El proyecto utiliza una arquitectura modular.

Cada componente tiene una responsabilidad específica.

## Componentes

### Ingestion
Lee registros de seguridad desde archivos JSON.

### Processing
Valida y normaliza los eventos.

### Detection
Evalúa los eventos mediante reglas configurables.

### Alerts
Genera y clasifica alertas.

### Investigation
Permite analizar alertas y documentar evidencias.

### Utils
Contiene funciones auxiliares compartidas.

## Flujo de procesamiento

Logs JSON → Ingestion → Processing → Detection → Alerts → Investigation