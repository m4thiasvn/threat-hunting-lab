# Threat Hunting Lab

Laboratorio práctico de ciberseguridad enfocado en desarrollar habilidades de análisis SOC y Threat Hunting mediante Python.

## Objetivo

Construir un sistema capaz de recopilar, procesar y analizar eventos de seguridad para identificar comportamientos sospechosos y generar alertas.

## Tecnologías

- Python 3.12
- JSON
- Git
- Docker (integración prevista para la etapa final)
- pytest (pruebas automatizadas)

## Arquitectura

```text
threat-hunting-lab/
├── data/               # Registros de seguridad
├── src/
│   ├── ingestion/      # Ingesta de eventos
│   ├── processing/     # Procesamiento y normalización
│   ├── detection/      # Motor de detección
│   ├── alerts/         # Gestión de alertas
│   ├── investigation/  # Investigación de incidentes
│   └── utils/          # Funciones auxiliares
├── rules/              # Reglas de detección
├── reports/            # Informes SOC
├── tests/              # Pruebas automatizadas
├── docs/               # Documentación
├── requirements.txt
├── README.md
└── .gitignore
```

## Detecciones previstas

- Ataques de fuerza bruta.
- Intentos de autenticación fallidos repetidos.
- Password spraying.
- Actividad sospechosa de usuarios.
- Direcciones IP sospechosas.

## Estado del proyecto

En desarrollo.

- [x] Preparación inicial del entorno.
- [ ] Ingesta de registros JSON.
- [ ] Normalización de eventos.
- [ ] Motor de detección.
- [ ] Sistema de alertas.
- [ ] Investigación de incidentes.
- [ ] Generación de informes.
- [ ] Integración con Docker.

## Ejecución

La guía de instalación y ejecución se completará conforme avance el desarrollo.

## Aviso

Este proyecto utiliza datos simulados y tiene fines educativos. No está diseñado para sustituir una plataforma SIEM de producción.