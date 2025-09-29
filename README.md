![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![CI](https://github.com/gasparswidzinski/Log_guardian)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)


# Log Guardian (paso a paso)

Herramienta **defensiva** para **análisis de logs** de Windows (CSV exportado) con detección de **ráfagas de fallos de login** (EventID 4625).  
Objetivo: demostrar **automatización**, **lógica de detección** y **generación de reportes** (CSV) de forma clara y profesional.

## Características (versión actual)
- Parser de **CSV** exportado del Visor de Eventos (Security).
- Regla: **failed_login_burst** → N fallos 4625 en una ventana de T minutos.
- **Configurable** mediante `config.toml`.
- **Exporta CSV** con hallazgos.

## Estructura
log-guardian/
├─ main.py
├─ config.toml
└─ samples/
    |__security_sample.csv

## Uso
```bash
# Activar entorno, luego:
python main.py --input .\samples\security_sample.csv --config .\config.toml --out .\out\findings.csv

## Logica de Deteccion
-Failed Login Burst (4625)
-Se agrupan eventos por (usuario, IP).
-Se usa una ventana deslizante de window_minutes.
-Si el conteo llega a threshold dentro de la ventana → hallazgo HIGH.
-Se exporta un CSV con timestamp, rule, severity, user, src_ip, host, message.
